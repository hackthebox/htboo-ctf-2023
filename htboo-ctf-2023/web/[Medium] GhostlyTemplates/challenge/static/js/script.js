function isCookieSet(name) {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith(name + "=")) {
            return true;
        }
    }
    return false;
}

window.onload = async () => {
    document.getElementById("templateButton").addEventListener("click", () => {
        window.location.href = "/view?page=" + document.getElementById("templateLink").value + "&remote=true";
    });

    if (isCookieSet("user_ip")) {
        return;
    }

    const response = await fetch("https://freeipapi.com/api/json/");

    if (response.status === 200) {
        const ipData = await response.json();

        const trueClientIP = ipData.ipAddress;

        document.cookie = `user_ip=${trueClientIP}; path=/`;
    } else {
        console.error("Failed to fetch IP data");
    }
}