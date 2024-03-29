from ttkthemes import ThemedTk
from tkinter import ttk
from tkinter.ttk import Treeview
import threading
import pyshark
import re


class App:
    capture = pyshark.LiveCapture(interface='Ethernet')

    def __init__(self, root):
        pattern = r"(\w+(?:\s\w+)*):\s*(.*)"
        self.data = {}
        self.regex = re.compile(pattern, re.MULTILINE)

        self.root = root
        self.root.title("IP Table")
        self.root.geometry("720x480")

        self.table = Treeview(self.root, columns=("Source IP", "Destination IP"), show="headings")
        self.table.heading("Source IP", text="Source IP")
        self.table.heading("Destination IP", text="Destination IP")
        self.table.pack(side="left")

        self.add_button = ttk.Button(self.root, text="Auto Update", command=self.update)
        self.add_button.pack(pady=5)

        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.table.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=self.scrollbar.set)

    def add_row(self):
        source_ip = "192.168.1.1"  # You can modify this to take input from the user
        dest_ip = "10.0.0.1"        # You can modify this to take input from the user
        self.table.insert("", "end", values=(source_ip, dest_ip))

    def update(self):
        while True:
            for packet in self.capture.sniff_continuously(packet_count=10):
                packet_str = f"{packet[1]}"

                matches = self.regex.findall(packet_str)
                for match in matches:
                    key = match[0]
                    value = match[1].strip()
                    self.data[key] = value
                print(f"SRC: {self.data['Source Address']}, DEST: {self.data['Destination Address']},")
                self.table.insert("", "end", values=(self.data['Source Address'], self.data['Destination Address']))


def main():
    root = ThemedTk(theme="arc")
    app = App(root)
    t1 = threading.Thread(target=root.mainloop())
    t1.start()
    t1.join()
    # root.mainloop()


if __name__ == '__main__':
    main()
