from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

@app.route('/', methods=['GET'])
def get_dns_requests():
    # Verbindung zur dns_requests Datenbank herstellen
    conn_dns = sqlite3.connect('dns_requests.db')
    c_dns = conn_dns.cursor()

    # Verbindung zur dhcp_name Datenbank herstellen
    conn_dhcp = sqlite3.connect('dhcp_name.db')
    c_dhcp = conn_dhcp.cursor()

    c_dns.execute("SELECT * FROM dns_requests")
    results = c_dns.fetchall()

    # Die Daten in ein geeignetes Format für die Vorlage umwandeln
    dns_data = {}
    for timestamp, ip, mac, dns in results:
        # Hostname für diese MAC-Adresse aus der dhcp_name-Datenbank abrufen
        c_dhcp.execute("SELECT dhcp_name FROM dhcp_name WHERE mac_address = ?", (mac,))
        result = c_dhcp.fetchone()
        hostname = result[0] if result else "Unknown"

        if mac not in dns_data:
            dns_data[mac] = {'hostname': hostname, 'requests': []}
        dns_data[mac]['requests'].append((timestamp, ip, dns))

    conn_dns.close()
    conn_dhcp.close()

    return render_template('dns_requests.html', dns_data=dns_data)

if __name__ == '__main__':
    app.run(debug=True)
