// qr_scanner.js
function startScanner(mealType) {
    const resultContainer = document.getElementById("qr-result");

    function onScanSuccess(decodedText, decodedResult) {
        console.log(`QR Code detected: ${decodedText}`);

        // Send QR data to Flask backend
        fetch("/scan_qr", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ qr_id: decodedText, meal_type: mealType }),
        })
        .then((response) => response.json())
        .then((data) => {
            resultContainer.innerText = data.message;
        })
        .catch((err) => {
            console.error(err);
        });
    }

    var html5QrCode = new Html5Qrcode("qr-reader");
    html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 250 },
        onScanSuccess
    );
}