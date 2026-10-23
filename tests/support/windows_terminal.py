"""ConPTY adapter for Rust CLI tests; requires pywinpty on Windows."""
import json
import os
import queue
import re
import sys
import threading
import time

from winpty import PtyProcess


def main():
    spec = json.loads(sys.argv[1])
    env = {key: value for key, value in spec["env"] if value is not None}
    # Windows console initialization needs the OS directory even for an env-cleared CLI.
    env["SystemRoot"] = os.environ["SystemRoot"]
    # String "0" selects ConPTY even in pywinpty versions using `backend or ...`.
    process = PtyProcess.spawn(
        spec["argv"], cwd=spec["cwd"], env=env, backend="0", dimensions=(40, 240)
    )
    chunks = queue.Queue()

    def read_output():
        try:
            while True:
                chunks.put(process.read())
        except EOFError:
            pass
        except Exception as error:
            chunks.put(error)
        finally:
            chunks.put(None)

    threading.Thread(target=read_output, daemon=True).start()
    transcript = ""
    next_answer = 0
    deadline = time.monotonic() + 90
    # ConPTY emits terminal escape sequences, including cursor positioning.
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")
    try:
        while True:
            if time.monotonic() > deadline:
                raise AssertionError(f"terminal timed out at prompt {next_answer}")
            try:
                chunk = chunks.get(timeout=0.1)
            except queue.Empty:
                continue
            if chunk is None:
                break
            if isinstance(chunk, Exception):
                raise chunk
            transcript += chunk
            clean = ansi.sub("", transcript)
            if next_answer < len(spec["answers"]):
                prompt, answer = spec["answers"][next_answer]
                if prompt in clean:
                    process.write(answer + "\r\n")
                    next_answer += 1
        if next_answer != len(spec["answers"]):
            raise AssertionError(f"only answered {next_answer} password prompts")
        while process.isalive():
            if time.monotonic() > deadline:
                raise AssertionError("terminal did not exit after EOF")
            time.sleep(0.01)
        clean = ansi.sub("", transcript)
        for _, answer in spec["answers"]:
            if answer and answer in clean:
                raise AssertionError("password was echoed in terminal output")
        sys.stderr.write(clean)
        status = process.exitstatus
        if status is None:
            raise AssertionError("terminal process returned no exit status")
        return status
    finally:
        process.close(force=True)


if __name__ == "__main__":
    sys.exit(main())
