import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import ssl
import paho.mqtt.client as mqtt


class MQTTClient:
    def __init__(self, log_callback, status_callback):
        self.client = None
        self.log_callback = log_callback
        self.status_callback = status_callback
        self.subscriptions = []

    def configure(self, config):
        self.config = config

        self.client = mqtt.Client(client_id=config['client_id'] or "")

        if config['username'] and config['password']:
            self.client.username_pw_set(config['username'], config['password'])

        if config['use_tls']:
            self.client.tls_set(
                ca_certs=config['ca_cert'] or None,
                certfile=config['client_cert'] or None,
                cert_reqs=ssl.CERT_REQUIRED
            )

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

    def connect(self):
        self.client.connect(
            self.config['broker'],
            int(self.config['port']),
            keepalive=int(self.config['keepalive'])
        )
        threading.Thread(target=self.client.loop_forever, daemon=True).start()
        self.log_callback(f"🌐 Connecting to {self.config['broker']}:{self.config['port']}...")
        self.status_callback("🔌 Connecting...", "#ffc107")

    def disconnect(self):
        if self.client:
            self.client.disconnect()

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.log_callback("✅ Connected.")
            self.status_callback("✅ Connected", "#28a745")
        else:
            self.log_callback(f"❌ Failed to connect (rc={rc})")
            self.status_callback("❌ Failed", "#dc3545")

    def on_disconnect(self, client, userdata, rc):
        self.log_callback("🔌 Disconnected.")
        self.status_callback("🔌 Disconnected", "#6c757d")

    def on_message(self, client, userdata, msg):
        self.log_callback(f"📥 [{msg.topic}] {msg.payload.decode(errors='ignore')}")

    def subscribe(self, topic, qos):
        if topic not in self.subscriptions:
            self.client.subscribe(topic, qos)
            self.subscriptions.append(topic)
            self.log_callback(f"🔔 Subscribed: {topic} (QoS {qos})")
        else:
            self.log_callback(f"⚠️ Already subscribed: {topic}")

    def unsubscribe(self, topic):
        if topic in self.subscriptions:
            self.client.unsubscribe(topic)
            self.subscriptions.remove(topic)
            self.log_callback(f"❌ Unsubscribed: {topic}")

    def publish(self, topic, payload, qos):
        self.client.publish(topic, payload, qos=qos)
        self.log_callback(f"📤 Published to {topic} (QoS {qos}): {payload}")


class ConfigWindow(tk.Toplevel):
    def __init__(self, master, on_save):
        super().__init__(master)
        self.title("MQTT Config")
        self.configure(bg="#f7f7f7")

        self.on_save = on_save

        self.entries = {}

        labels = [
            ("Broker:", "broker", "test.mosquitto.org"),
            ("Port:", "port", "1883"),
            ("Username:", "username", ""),
            ("Password:", "password", ""),
            ("Client ID:", "client_id", ""),
            ("Keepalive (sec):", "keepalive", "60")
        ]

        for i, (label, key, default) in enumerate(labels):
            tk.Label(self, text=label, bg="#f7f7f7").grid(row=i, column=0, sticky="w", padx=10, pady=5)
            entry = tk.Entry(self, width=35)
            entry.insert(0, default)
            entry.grid(row=i, column=1, padx=10, pady=5)
            self.entries[key] = entry

        self.use_tls = tk.BooleanVar()
        tk.Checkbutton(self, text="Enable TLS", variable=self.use_tls, bg="#f7f7f7").grid(row=6, column=1, sticky="w", padx=10, pady=5)

        tk.Label(self, text="CA Cert:", bg="#f7f7f7").grid(row=7, column=0, sticky="w", padx=10, pady=5)
        self.ca_cert = tk.Entry(self, width=35)
        self.ca_cert.grid(row=7, column=1, padx=10, pady=5)
        tk.Button(self, text="Browse", command=self.browse_ca).grid(row=7, column=2, padx=5)

        tk.Label(self, text="Client Cert:", bg="#f7f7f7").grid(row=8, column=0, sticky="w", padx=10, pady=5)
        self.client_cert = tk.Entry(self, width=35)
        self.client_cert.grid(row=8, column=1, padx=10, pady=5)
        tk.Button(self, text="Browse", command=self.browse_client_cert).grid(row=8, column=2, padx=5)

        tk.Button(self, text="Save", bg="#007bff", fg="white", command=self.save).grid(row=9, column=0, columnspan=3, pady=15)

    def browse_ca(self):
        path = filedialog.askopenfilename()
        if path:
            self.ca_cert.delete(0, tk.END)
            self.ca_cert.insert(0, path)

    def browse_client_cert(self):
        path = filedialog.askopenfilename()
        if path:
            self.client_cert.delete(0, tk.END)
            self.client_cert.insert(0, path)

    def save(self):
        config = {key: entry.get() for key, entry in self.entries.items()}
        config['use_tls'] = self.use_tls.get()
        config['ca_cert'] = self.ca_cert.get()
        config['client_cert'] = self.client_cert.get()
        self.on_save(config)
        self.destroy()


class MQTTGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MQTT Client Pro")

        self.client = MQTTClient(self.log, self.update_status)

        # Layout
        top = tk.Frame(root, bg="#ffffff")
        top.pack(fill="x", padx=10, pady=5)

        tk.Button(top, text="⚙️ Config", command=self.open_config).pack(side="left", padx=5)
        tk.Button(top, text="Connect", command=self.connect, bg="#28a745", fg="white").pack(side="left", padx=5)
        tk.Button(top, text="Disconnect", command=self.disconnect, bg="#dc3545", fg="white").pack(side="left", padx=5)
        tk.Button(top, text="Clear Log", command=self.clear_log, bg="#6c757d", fg="white").pack(side="right", padx=5)

        sub = tk.LabelFrame(root, text="Subscribe")
        sub.pack(fill="x", padx=10, pady=5)

        self.sub_topic = tk.Entry(sub, width=40)
        self.sub_topic.grid(row=0, column=0, padx=5, pady=5)

        self.sub_qos = ttk.Combobox(sub, values=[0, 1, 2], width=3)
        self.sub_qos.current(0)
        self.sub_qos.grid(row=0, column=1, padx=5)

        tk.Button(sub, text="Subscribe", command=self.subscribe).grid(row=0, column=2, padx=5)
        tk.Button(sub, text="Unsubscribe Selected", command=self.unsubscribe).grid(row=0, column=3, padx=5)

        self.sub_list = tk.Listbox(sub, height=4)
        self.sub_list.grid(row=1, column=0, columnspan=4, sticky="we", padx=5, pady=5)

        pub = tk.LabelFrame(root, text="Publish")
        pub.pack(fill="x", padx=10, pady=5)

        self.pub_topic = tk.Entry(pub, width=40)
        self.pub_topic.grid(row=0, column=0, padx=5, pady=5)
        self.pub_msg = tk.Entry(pub, width=40)
        self.pub_msg.grid(row=0, column=1, padx=5, pady=5)

        self.pub_qos = ttk.Combobox(pub, values=[0, 1, 2], width=3)
        self.pub_qos.current(0)
        self.pub_qos.grid(row=0, column=2, padx=5)

        tk.Button(pub, text="Publish", command=self.publish).grid(row=0, column=3, padx=5)

        self.log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=5)

        self.status = tk.StringVar(value="🔌 Disconnected")
        self.status_bar = tk.Label(root, textvariable=self.status, bg="#6c757d", fg="white")
        self.status_bar.pack(fill="x", side="bottom")

    def open_config(self):
        ConfigWindow(self.root, self.apply_config)

    def apply_config(self, config):
        self.client.configure(config)
        self.log("✅ Config applied")

    def connect(self):
        try:
            self.client.connect()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {e}")

    def disconnect(self):
        self.client.disconnect()

    def subscribe(self):
        topic = self.sub_topic.get()
        qos = int(self.sub_qos.get())
        self.client.subscribe(topic, qos)
        self.sub_list.insert(tk.END, topic)

    def unsubscribe(self):
        selected = self.sub_list.curselection()
        if selected:
            topic = self.sub_list.get(selected)
            self.client.unsubscribe(topic)
            self.sub_list.delete(selected)

    def publish(self):
        topic = self.pub_topic.get()
        msg = self.pub_msg.get()
        qos = int(self.pub_qos.get())
        self.client.publish(topic, msg, qos)

    def clear_log(self):
        self.log_box.delete("1.0", tk.END)

    def log(self, text):
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)

    def update_status(self, text, color):
        self.status.set(text)
        self.status_bar.config(bg=color)


if __name__ == "__main__":
    root = tk.Tk()
    app = MQTTGUI(root)
    root.mainloop()
