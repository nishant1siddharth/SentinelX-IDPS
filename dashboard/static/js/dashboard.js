
async function loadAlerts() {
    const table = document.getElementById("alerts-table");
    const totalAlerts = document.getElementById("total-alerts");

    try {
        const response = await fetch("/api/alerts");

        if (!response.ok) {
            throw new Error("Unable to fetch alerts");
        }

        const data = await response.json();

        totalAlerts.textContent = data.total;

        table.replaceChildren();

        if (data.alerts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "No security alerts detected.";

            row.appendChild(cell);
            table.appendChild(row);
            return;
        }

        data.alerts.forEach(alert => {
            const row = document.createElement("tr");

            const timestamp = alert.timestamp
                ? new Date(alert.timestamp).toLocaleString()
                : "Unknown";

       const severity = {
                1: "HIGH",
                2: "MEDIUM",
                3: "LOW"
            }[alert.severity] || "UNKNOWN";

            const values = [
                timestamp,
                severity,
                alert.source_ip || "Unknown",
                alert.destination_ip || "Unknown",
                alert.signature || "Unknown alert"
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            });

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Dashboard error:", error);
        totalAlerts.textContent = "--";
        table.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "Unable to load security alerts.";

        row.appendChild(cell);
        table.appendChild(row);
    }
}

loadAlerts();
setInterval(loadAlerts, 10000);


async function loadBlockedIPs() {
    const blockedElement = document.getElementById("blocked-ips");
    const table = document.getElementById("blocked-ips-table");

    try {
        const response = await fetch("/api/blocked-ips");

        if (!response.ok) {
            throw new Error("Unable to fetch blocked IPs");
        }

        const data = await response.json();

        // Update blocked IP count
        blockedElement.textContent = data.total;

        // Clear previous table contents
        table.replaceChildren();

        if (data.blocked_ips.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 2;
            cell.textContent = "No IP addresses are currently blocked.";

            row.appendChild(cell);
            table.appendChild(row);
            return;
        }

        data.blocked_ips.forEach(ip => {
            const row = document.createElement("tr");

            const ipCell =  document.createElement("td");
            ipCell.textContent = ip;

            const statusCell = document.createElement("td");
            statusCell.textContent = "BLOCKED";

            row.appendChild(ipCell);
            row.appendChild(statusCell);

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Blocklist error:", error);
        blockedElement.textContent = "--";

        table.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 2;
        cell.textContent = "Unable to load firewall blocklist.";

        row.appendChild(cell);
        table.appendChild(row);
    }
}
loadAlerts();
setInterval(loadAlerts, 10000);

loadBlockedIPs();
setInterval(loadBlockedIPs, 10000);
