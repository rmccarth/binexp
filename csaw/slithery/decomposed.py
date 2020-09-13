#!/usr/bin/env python3
from base64 import b64decode
import blacklist  # you don't get to see this :p

"""
Don't worry, if you break out of this one, we have another one underneath so that you won't
wreak any havoc!
"""

def main():
    print("EduPy 3.8.2")
    while True:
        try:
            command = input(">>> ")
            if any([x in command for x in blacklist.BLACKLIST]):
                raise Exception("not allowed!!")

            final_cmd = """
sandboxFile = open("sandbox.py", "r")
numberOne = int(((54 * 8) / 16) * (1/3) - 8)
sandboxLines = sandboxFile.readlines()[numberOne].strip().split(" ")    # from base64 import b64decode
secondLine = sandboxLines[numberOne]
secondToLastLine = sandboxLines[-numberOne]
sandboxFile.close()
b64_decode = getattr(__import__(secondLine), secondToLastLine) # gets attribute secondLine.secondToLastLine
RMbPOQHCzt = __builtins__.__dict__[b64_decode(b'__import__')](b64_decode(b'numpy'))\n""" + command
            exec(final_cmd)

        except (KeyboardInterrupt, EOFError):
            return 0
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    exit(main())
