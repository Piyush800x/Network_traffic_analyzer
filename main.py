import os
import sys
from tkinter.ttk import Treeview, Scrollbar, Combobox, Frame
from tkinter.ttk import Button as NewButton
import tkinter as tk
import threading
import pyshark
import re
import ipinfo
from dotenv import load_dotenv
from tkinter import Toplevel, StringVar, Label, messagebox
from pyshark.capture.live_capture import UnknownInterfaceException
from ttkthemes import ThemedTk

load_dotenv()
global adapter
font_heading = ("Arial", 14)
font_content = ("Arial", 12)


class GUI(Toplevel):

    def __init__(self):
        global adapter
        super().__init__()
        self.protocol('WM_DELETE_WINDOW', lambda: [sys.exit(0)])
        self.ip_handler = ipinfo.getHandler(os.getenv("IPINFO_TOKEN"))
        self.capture = pyshark.LiveCapture(interface=f'{adapter}')

        pattern = r"(\w+(?:\s\w+)*):\s*(.*)"
        self.data = {}
        self.regex = re.compile(pattern, re.MULTILINE)

        self.frame_1 = Frame(self, width=500, height=300)
        self.frame_1.pack()

        self.tree = Treeview(self, columns=("SRC", "DEST"), show="headings", height=300)

        self.tree.heading("SRC", text="SRC")
        self.tree.heading("DEST", text="DEST")

        self.tree.column("SRC", width=100)
        self.tree.column("DEST", width=100)

        self.tree.pack(expand=True, fill="both")

        self.scrollbar = Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.tag_configure("my_font", font=font_content)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.update_data()

    def update_data(self):
        def update():
            while True:
                try:
                    for packet in self.capture.sniff_continuously(packet_count=10):
                        packet_str = f"{packet[1]}"

                        matches = self.regex.findall(packet_str)
                        for match in matches:
                            key = match[0]
                            value = match[1].strip()
                            self.data[key] = value
                        print(f"SRC: {self.data['Source Address']}, DEST: {self.data['Destination Address']},")

                        src_1 = str
                        dest_1 = str
                        # Checking if src has hostname
                        try:
                            src = self.ip_handler.getDetails(self.data['Source Address']).details["hostname"]
                            src_1 = src
                        except KeyError:
                            src = self.data['Source Address']
                            src_1 = src

                        # Checking if dest has hostname
                        try:
                            dest = self.ip_handler.getDetails(self.data['Destination Address']).details["hostname"]
                            dest_1 = dest
                        except KeyError:
                            dest = self.data['Destination Address']
                            dest_1 = dest

                        # Finally, updating the table
                        self.tree.insert("", "end", values=(src_1, dest_1))

                        # Auto Scroll
                        self.tree.yview_moveto(1.0)
                except UnknownInterfaceException:
                    messagebox.showerror("NTA", "Wrong interface selected!\nTry again.")
        threading.Thread(target=update, daemon=True).start()


class PreWindow(ThemedTk):

    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analyzer")
        self.geometry("270x180")

        adapter_var: StringVar = StringVar()

        self.adapter_label: Label = Label(self, text="Network Adapter")
        self.adapter_label.pack()

        self.adapter_entry: Combobox = Combobox(self, textvariable=adapter_var)
        self.adapter_entry['values'] = ['Ethernet', "Wi-Fi"]
        self.adapter_entry.current(0)
        self.adapter_entry.pack()

        self.btn = NewButton(self, text="Start", command=lambda: [self.withdraw(), start(self.adapter_entry.get())])
        self.btn.pack()


def start(adapter_):
    global adapter
    adapter = adapter_
    app = GUI()
    app.mainloop()


def main():
    window = PreWindow()
    window.mainloop()


if __name__ == '__main__':
    main()
