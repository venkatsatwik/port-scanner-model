const scanButton = document.getElementById("scanBtn");

const targetInput = document.getElementById("target");

const scanStatus = document.getElementById("scanStatus");

const scanBadge = document.getElementById("scanBadge");

const progress = document.getElementById("progress");

const resultsBody = document.getElementById("resultsBody");

const portsCounter = document.getElementById("ports");


const scanResults = [

    {
        port: 22,
        state: "OPEN",
        service: "SSH",
        version: "OpenSSH 9.2"
    },

    {
        port: 80,
        state: "OPEN",
        service: "HTTP",
        version: "Apache 2.4"
    },

    {
        port: 443,
        state: "OPEN",
        service: "HTTPS",
        version: "Apache 2.4"
    },

    {
        port: 3306,
        state: "OPEN",
        service: "MySQL",
        version: "MySQL 8.0"
    },

    {
        port: 21,
        state: "CLOSED",
        service: "FTP",
        version: "-"
    },

    {
        port: 23,
        state: "CLOSED",
        service: "Telnet",
        version: "-"
    }

];


scanButton.addEventListener("click", startScan);


function startScan() {

    const target = targetInput.value.trim();


    if (target === "") {

        scanStatus.textContent =
            "Enter a target IP address.";

        return;
    }


    scanButton.disabled = true;

    scanButton.textContent = "Scanning...";

    scanStatus.textContent =
        `Scanning ${target}`;

    scanBadge.textContent = "SCANNING";

    resultsBody.innerHTML = "";

    progress.style.width = "0%";


    let percentage = 0;


    const scanner = setInterval(() => {

        percentage += 5;

        progress.style.width =
            percentage + "%";


        if (percentage >= 100) {

            clearInterval(scanner);

            finishScan(target);
        }

    }, 80);

}


function finishScan(target) {

    scanStatus.textContent =
        `Scan completed: ${target}`;

    scanBadge.textContent = "COMPLETE";

    scanButton.disabled = false;

    scanButton.textContent = "Scan Target";


    resultsBody.innerHTML = "";


    scanResults.forEach(result => {

        const row =
            document.createElement("tr");


        const stateClass =
            result.state === "OPEN"
                ? "open"
                : "closed";


        row.innerHTML = `

            <td>${result.port}/tcp</td>

            <td class="${stateClass}">
                ${result.state}
            </td>

            <td>${result.service}</td>

            <td>${result.version}</td>

        `;


        resultsBody.appendChild(row);

    });


    portsCounter.textContent =
        scanResults.filter(
            result => result.state === "OPEN"
        ).length;

}