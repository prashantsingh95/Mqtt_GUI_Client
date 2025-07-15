import sys
import os
import ssl
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QTextEdit, QListWidget, QComboBox, QMessageBox, QDialog,
    QFormLayout, QFileDialog
)
from PyQt6.QtCore import Qt
import paho.mqtt.client as mqtt


# === Helper to find resource files ===
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)


# === Config dialog ===
class ConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("MQTT Configuration")
        self.setFixedWidth(500)

        layout = QFormLayout()

        self.broker_input = QLineEdit("test.mosquitto.org")
        self.port_input = QLineEdit("8883")
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.client_id_input = QLineEdit()
        self.keepalive_input = QLineEdit("60")
        self.use_tls = QComboBox()
        self.use_tls.addItems(["No", "Yes"])

        self.ca_cert_input = QLineEdit()
        self.ca_cert_btn = QPushButton("Browse")
        self.ca_cert_btn.clicked.connect(self.browse_ca)

        self.client_cert_input = QLineEdit()
        self.client_cert_btn = QPushButton("Browse")
        self.client_cert_btn.clicked.connect(self.browse_client_cert)

        self.client_key_input = QLineEdit()
        self.client_key_btn = QPushButton("Browse")
        self.client_key_btn.clicked.connect(self.browse_client_key)

        ca_layout = QHBoxLayout()
        ca_layout.addWidget(self.ca_cert_input)
        ca_layout.addWidget(self.ca_cert_btn)

        client_cert_layout = QHBoxLayout()
        client_cert_layout.addWidget(self.client_cert_input)
        client_cert_layout.addWidget(self.client_cert_btn)

        client_key_layout = QHBoxLayout()
        client_key_layout.addWidget(self.client_key_input)
        client_key_layout.addWidget(self.client_key_btn)

        layout.addRow("Broker:", self.broker_input)
        layout.addRow("Port:", self.port_input)
        layout.addRow("Username:", self.username_input)
        layout.addRow("Password:", self.password_input)
        layout.addRow("Client ID:", self.client_id_input)
        layout.addRow("Keepalive:", self.keepalive_input)
        layout.addRow("Use TLS:", self.use_tls)
        layout.addRow("CA Cert Path:", ca_layout)
        layout.addRow("Client Cert Path:", client_cert_layout)
        layout.addRow("Client Key Path:", client_key_layout)

        self.ok_btn = QPushButton("Apply & Close")
        self.ok_btn.clicked.connect(self.accept)
        layout.addRow(self.ok_btn)

        self.setLayout(layout)

    def browse_ca(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select CA Certificate")
        if path:
            self.ca_cert_input.setText(path)

    def browse_client_cert(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Client Certificate")
        if path:
            self.client_cert_input.setText(path)

    def browse_client_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Client Key")
        if path:
            self.client_key_input.setText(path)

    def get_config(self):
        return {
            'broker': self.broker_input.text(),
            'port': self.port_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'client_id': self.client_id_input.text(),
            'keepalive': self.keepalive_input.text(),
            'use_tls': self.use_tls.currentText() == "Yes",
            'ca_cert': self.ca_cert_input.text(),
            'client_cert': self.client_cert_input.text(),
            'client_key': self.client_key_input.text()
        }


# === MQTT client ===
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
                keyfile=config['client_key'] or None,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS_CLIENT
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
        self.status_callback("Connecting...")

    def disconnect(self):
        if self.client:
            self.client.disconnect()

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.log_callback("✅ Connected.")
            self.status_callback("Connected ✅")
        else:
            self.log_callback(f"❌ Failed to connect (rc={rc})")
            self.status_callback("Failed ❌")

    def on_disconnect(self, client, userdata, rc):
        self.log_callback("🔌 Disconnected.")
        self.status_callback("Disconnected ❌")

    def on_message(self, client, userdata, msg):
        self.log_callback(f"📥 [{msg.topic}] {msg.payload.decode(errors='ignore')}")

    def subscribe(self, topic, qos):
        if topic not in self.subscriptions:
            self.client.subscribe(topic, qos)
            self.subscriptions.append(topic)
            self.log_callback(f"🔔 Subscribed: {topic} (QoS {qos})")

    def unsubscribe(self, topic):
        if topic in self.subscriptions:
            self.client.unsubscribe(topic)
            self.subscriptions.remove(topic)
            self.log_callback(f"❌ Unsubscribed: {topic}")

    def publish(self, topic, payload, qos):
        self.client.publish(topic, payload, qos=qos)
        self.log_callback(f"📤 Published to {topic} (QoS {qos}): {payload}")


# === Main GUI ===
class MQTTGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MQTT Client Pro — PyQt6")
        self.resize(900, 600)
        self.client = MQTTClient(self.log, self.update_status)
        self.setup_ui()

        # ✅ Use safe resource path for QSS
        qss_file = resource_path("style.qss")
        if os.path.exists(qss_file):
            with open(qss_file, "r") as f:
                self.setStyleSheet(f.read())
        else:
            print("⚠️ style.qss not found — using default style.")

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        top_bar = QHBoxLayout()
        self.config_btn = QPushButton("⚙️ Config")
        self.connect_btn = QPushButton("🔗 Connect")
        self.disconnect_btn = QPushButton("❌ Disconnect")
        self.clear_btn = QPushButton("🧹 Clear Log")

        top_bar.addWidget(self.config_btn)
        top_bar.addWidget(self.connect_btn)
        top_bar.addWidget(self.disconnect_btn)
        top_bar.addStretch()
        top_bar.addWidget(self.clear_btn)
        layout.addLayout(top_bar)

        sub_layout = QHBoxLayout()
        self.sub_topic = QLineEdit()
        self.sub_topic.setPlaceholderText("Subscribe topic")
        self.sub_qos = QComboBox()
        self.sub_qos.addItems(["0", "1", "2"])
        self.sub_btn = QPushButton("➕ Subscribe")
        self.unsub_btn = QPushButton("➖ Unsubscribe")

        sub_layout.addWidget(self.sub_topic)
        sub_layout.addWidget(self.sub_qos)
        sub_layout.addWidget(self.sub_btn)
        sub_layout.addWidget(self.unsub_btn)
        layout.addLayout(sub_layout)

        self.sub_list = QListWidget()
        layout.addWidget(self.sub_list)

        pub_layout = QHBoxLayout()
        self.pub_topic = QLineEdit()
        self.pub_topic.setPlaceholderText("Publish topic")
        self.pub_msg = QLineEdit()
        self.pub_msg.setPlaceholderText("Message")
        self.pub_qos = QComboBox()
        self.pub_qos.addItems(["0", "1", "2"])
        self.pub_btn = QPushButton("🚀 Publish")

        pub_layout.addWidget(self.pub_topic)
        pub_layout.addWidget(self.pub_msg)
        pub_layout.addWidget(self.pub_qos)
        pub_layout.addWidget(self.pub_btn)
        layout.addLayout(pub_layout)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

        self.status_bar = QLabel("Disconnected ❌")
        layout.addWidget(self.status_bar)

        self.config_btn.clicked.connect(self.open_config)
        self.connect_btn.clicked.connect(self.connect)
        self.disconnect_btn.clicked.connect(self.disconnect)
        self.clear_btn.clicked.connect(self.clear_log)
        self.sub_btn.clicked.connect(self.subscribe)
        self.unsub_btn.clicked.connect(self.unsubscribe)
        self.pub_btn.clicked.connect(self.publish)

    def open_config(self):
        dlg = ConfigDialog(self)
        if dlg.exec():
            self.client.configure(dlg.get_config())
            self.log("✅ Config applied")

    def connect(self):
        try:
            self.client.connect()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Connect failed: {e}")

    def disconnect(self):
        self.client.disconnect()

    def subscribe(self):
        topic = self.sub_topic.text().strip()
        qos = int(self.sub_qos.currentText())
        if topic:
            self.client.subscribe(topic, qos)
            self.sub_list.addItem(topic)

    def unsubscribe(self):
        for item in self.sub_list.selectedItems():
            topic = item.text()
            self.client.unsubscribe(topic)
            self.sub_list.takeItem(self.sub_list.row(item))

    def publish(self):
        topic = self.pub_topic.text().strip()
        msg = self.pub_msg.text()
        qos = int(self.pub_qos.currentText())
        if topic:
            self.client.publish(topic, msg, qos)

    def clear_log(self):
        self.log_box.clear()

    def log(self, text):
        self.log_box.append(text)

    def update_status(self, text):
        self.status_bar.setText(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = MQTTGUI()
    gui.show()
    sys.exit(app.exec())
