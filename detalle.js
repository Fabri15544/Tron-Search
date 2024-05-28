document.addEventListener("DOMContentLoaded", function () {
    var urlParams = new URLSearchParams(window.location.search);
    var ip = urlParams.get('ip');

    if (ip) {
        document.getElementById("ip-address").textContent = ip;

        fetch('datos.json')
            .then(response => response.json())
            .then(data => {
                var detalles = data.filter(item => item.IP === ip);

                if (detalles.length > 0) {
                    var detallesBody = document.getElementById("detalles-body");
                    detallesBody.innerHTML = ""; // Clear previous rows

                    detalles.forEach(detalle => {
                        var row = detallesBody.insertRow();
                        ["Puerto", "Servicio", "Región", "Banner", "Ciudad", "Dominio", "CredencialesDVR", "SistemaOperativo_RDP", "Fecha", "SistemaOperativo_SMB", "Nombre-PC", "Camara", "Preview"].forEach(function (field) {
                            var cell = row.insertCell();
                            if (field === "Preview" && detalle[field] === "has_screenshot:true") {
                                var imagePath = `screenshot/${detalle.IP}-${detalle.Puerto}.png`;
                                cell.innerHTML = `<div style="text-align: center;"><img src="${imagePath}" alt="Screenshot" style="max-width: 512px;"></div>`;
                            } else {
                                cell.textContent = detalle[field] || "N/A";
                            }
                        });
                    });
                } else {
                    alert("No se encontraron detalles para esta IP.");
                }
            })
            .catch(error => {
                console.error('Error al cargar los detalles:', error);
            });
    } else {
        alert("No se proporcionó una IP válida.");
    }
});
