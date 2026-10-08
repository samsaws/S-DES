# main.py

import tkinter as tk
from gui.main_window import SDESApp

def main():
    root = tk.Tk()
    app = SDESApp(root)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()