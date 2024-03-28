from scapy.all import sniff, IP
import pandas as pd
from tkinter import *


def capture_traffic(duration=10):
  packets = sniff(iface="Wi-Fi", count=100, timeout=duration)  # Replace "eth0" with your network interface
  return packets


def analyze_packets(packets):
  data = []
  for packet in packets:
    data.append({
      "source_ip": packet[IP].src,
      "destination_ip": packet[IP].dst,
      "protocol": packet[IP].proto,
      "length": len(packet)
    })
  df = pd.DataFrame(data)
  return df

def start_capture(duration_entry):
  # Get capture duration from entry field
  try:
    duration = int(duration_entry.get())
  except ValueError:
    return
  packets = capture_traffic(duration)
  df = analyze_packets(packets)
  # Update data table with captured data (implementation omitted for brevity)

def main():
  # Create main window
  root = Tk()
  root.title("Network Traffic Analyzer")

  # Label and entry for capture duration
  duration_label = Label(root, text="Capture Duration (seconds):")
  duration_label.pack()
  duration_entry = Entry(root)
  duration_entry.insert(0, "10")  # Default value
  duration_entry.pack()

  # Button to start capture
  capture_button = Button(root, text="Start Capture", command=lambda: start_capture(duration_entry))
  capture_button.pack()
  
  root.mainloop()

if __name__ == "__main__":
  main()
