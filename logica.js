function cargarDatos(callback) {
    var xhr = new XMLHttpRequest();
    xhr.overrideMimeType("application/json");
    xhr.open('GET', 'datos.json', true);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            callback(JSON.parse(xhr.responseText));
        }
    };
    xhr.send(null);
}

function cargarOpcionesDePuerto(datos) {
    var puertoFilter = document.getElementById("puertoFilter");
    var Puertos = [];

    datos.forEach(resultado => {
        if (!Puertos.includes(resultado.Puerto)) {
            Puertos.push(resultado.Puerto);
            var option = document.createElement("option");
            option.value = resultado.Puerto;
            option.textContent = resultado.Puerto;
            puertoFilter.appendChild(option);
        }
    });
}

function cargarOpcionesDeServicio(datos) {
    var servicioFilter = document.getElementById("servicioFilter");
    var servicios = [];

    datos.forEach(resultado => {
        if (!servicios.includes(resultado.Servicio)) {
            servicios.push(resultado.Servicio);
            var option = document.createElement("option");
            option.value = resultado.Servicio;
            option.textContent = resultado.Servicio;
            servicioFilter.appendChild(option);
        }
    });
}


cargarDatos(datos => {
    cargarOpcionesDeServicio(datos);
    cargarOpcionesDePuerto(datos);
});

function actualizarListaPeriodicamente() {
    setInterval(() => {
        cargarDatos(datos => {
            var servicioFilter = document.getElementById("servicioFilter");
            servicioFilter.innerHTML = '';
            cargarOpcionesDeServicio(datos);
        });
    }, 2000); // Actualizar cada 60 segundos (ajustar según sea necesario)
}

function getFlagEmoji(region) {
    // Create a mapping of regions to flag emojis
    const flagMap = {
        "Afghanistan": "🇦🇫",
        "Turkey": "🇹🇷",
        "Türkiye": "🇹🇷",
        "Albania": "🇦🇱",
        "Algeria": "🇩🇿",
        "Andorra": "🇦🇩",
        "Angola": "🇦🇴",
        "Antigua and Barbuda": "🇦🇬",
        "Argentina": "🇦🇷",
        "Armenia": "🇦🇲",
        "Australia": "🇦🇺",
        "Austria": "🇦🇹",
        "Azerbaijan": "🇦🇿",
        "Bahamas": "🇧🇸",
        "Bahrain": "🇧🇭",
        "Bangladesh": "🇧🇩",
        "Barbados": "🇧🇧",
        "Belarus": "🇧🇾",
        "Belgium": "🇧🇪",
        "Belize": "🇧🇿",
        "Benin": "🇧🇯",
        "Bhutan": "🇧🇹",
        "Bolivia": "🇧🇴",
        "Bosnia and Herzegovina": "🇧🇦",
        "Botswana": "🇧🇼",
        "Brazil": "🇧🇷",
        "Brunei": "🇧🇳",
        "Bulgaria": "🇧🇬",
        "Burkina Faso": "🇧🇫",
        "Burundi": "🇧🇮",
        "Cabo Verde": "🇨🇻",
        "Cambodia": "🇰🇭",
        "Cameroon": "🇨🇲",
        "Canada": "🇨🇦",
        "Central African Republic": "🇨🇫",
        "Chad": "🇹🇩",
        "Chile": "🇨🇱",
        "China": "🇨🇳",
        "Colombia": "🇨🇴",
        "Comoros": "🇰🇲",
        "Congo (Congo-Brazzaville)": "🇨🇬",
        "Costa Rica": "🇨🇷",
        "Croatia": "🇭🇷",
        "Cuba": "🇨🇺",
        "Cyprus": "🇨🇾",
        "Czechia (Czech Republic)": "🇨🇿",
        "Democratic Republic of the Congo (Congo-Kinshasa)": "🇨🇩",
        "Denmark": "🇩🇰",
        "Djibouti": "🇩🇯",
        "Dominica": "🇩🇲",
        "Dominican Republic": "🇩🇴",
        "Ecuador": "🇪🇨",
        "Egypt": "🇪🇬",
        "El Salvador": "🇸🇻",
        "Equatorial Guinea": "🇬🇶",
        "Eritrea": "🇪🇷",
        "Estonia": "🇪🇪",
        "Eswatini": "fmr",
        "Swaziland": "🇸🇿",
        "Ethiopia": "🇪🇹",
        "Fiji": "🇫🇯",
        "Finland": "🇫🇮",
        "France": "🇫🇷",
        "Gabon": "🇬🇦",
        "Gambia": "🇬🇲",
        "Georgia": "🇬🇪",
        "Germany": "🇩🇪",
        "Ghana": "🇬🇭",
        "Greece": "🇬🇷",
        "Grenada": "🇬🇩",
        "Guatemala": "🇬🇹",
        "Guinea": "🇬🇳",
        "Guinea-Bissau": "🇬🇼",
        "Guyana": "🇬🇾",
        "Haiti": "🇭🇹",
        "Holy See": "🇻🇦",
        "Honduras": "🇭🇳",
        "Hungary": "🇭🇺",
        "Iceland": "🇮🇸",
        "India": "🇮🇳",
        "Indonesia": "🇮🇩",
        "Iran": "🇮🇷",
        "Iraq": "🇮🇶",
        "Ireland": "🇮🇪",
        "Israel": "🇮🇱",
        "Italy": "🇮🇹",
        "Ivory Coast": "🇨🇮",
        "Jamaica": "🇯🇲",
        "Japan": "🇯🇵",
        "Jordan": "🇯🇴",
        "Kazakhstan": "🇰🇿",
        "Kenya": "🇰🇪",
        "Kiribati": "🇰🇮",
        "Kuwait": "🇰🇼",
        "Kyrgyzstan": "🇰🇬",
        "Laos": "🇱🇦",
        "Latvia": "🇱🇻",
        "Lebanon": "🇱🇧",
        "Lesotho": "🇱🇸",
        "Liberia": "🇱🇷",
        "Libya": "🇱🇾",
        "Liechtenstein": "🇱🇮",
        "Lithuania": "🇱🇹",
        "Luxembourg": "🇱🇺",
        "Madagascar": "🇲🇬",
        "Malawi": "🇲🇼",
        "Malaysia": "🇲🇾",
        "Maldives": "🇲🇻",
        "Mali": "🇲🇱",
        "Malta": "🇲🇹",
        "Marshall Islands": "🇲🇭",
        "Mauritania": "🇲🇷",
        "Mauritius": "🇲🇺",
        "Mexico": "🇲🇽",
        "Micronesia": "🇫🇲",
        "Moldova": "🇲🇩",
        "Monaco": "🇲🇨",
        "Mongolia": "🇲🇳",
        "Montenegro": "🇲🇪",
        "Morocco": "🇲🇦",
        "Mozambique": "🇲🇿",
        "Myanmar (formerly Burma)": "🇲🇲",
        "Namibia": "🇳🇦",
        "Nauru": "🇳🇷",
        "Nepal": "🇳🇵",
        "Netherlands": "🇳🇱",
        "New Zealand": "🇳🇿",
        "Nicaragua": "🇳🇮",
        "Niger": "🇳🇪",
        "Nigeria": "🇳🇬",
        "North Korea": "🇰🇵",
        "North Macedonia": "🇲🇰",
        "Norway": "🇳🇴",
        "Oman": "🇴🇲",
        "Pakistan": "🇵🇰",
        "Palau": "🇵🇼",
        "Palestine State": "🇵🇸",
        "Panama": "🇵🇦",
        "Papua New Guinea": "🇵🇬",
        "Paraguay": "🇵🇾",
        "Peru": "🇵🇪",
        "Philippines": "🇵🇭",
        "Poland": "🇵🇱",
        "Portugal": "🇵🇹",
        "Qatar": "🇶🇦",
        "Romania": "🇷🇴",
        "Russia": "🇷🇺",
        "Rwanda": "🇷🇼",
        "Saint Kitts and Nevis": "🇰🇳",
        "Saint Lucia": "🇱🇨",
        "Saint Vincent and the Grenadines": "🇻🇨",
        "Samoa": "🇼🇸",
        "San Marino": "🇸🇲",
        "Sao Tome and Principe": "🇸🇹",
        "Saudi Arabia": "🇸🇦",
        "Senegal": "🇸🇳",
        "Serbia": "🇷🇸",
        "Seychelles": "🇸🇨",
        "Sierra Leone": "🇸🇱",
        "Singapore": "🇸🇬",
        "Slovakia": "🇸🇰",
        "Slovenia": "🇸🇮",
        "Solomon Islands": "🇸🇧",
        "Somalia": "🇸🇴",
        "South Africa": "🇿🇦",
        "South Korea": "🇰🇷",
        "South Sudan": "🇸🇸",
        "Spain": "🇪🇸",
        "Sri Lanka": "🇱🇰",
        "Sudan": "🇸🇩",
        "Suriname": "🇸🇷",
        "Sweden": "🇸🇪",
        "Switzerland": "🇨🇭",
        "Syria": "🇸🇾",
        "Tajikistan": "🇹🇯",
        "Tanzania": "🇹🇿",
        "Thailand": "🇹🇭",
        "Timor-Leste": "🇹🇱",
        "Togo": "🇹🇬",
        "Tonga": "🇹🇴",
        "Trinidad and Tobago": "🇹🇹",
        "Tunisia": "🇹🇳",
        "Turkey": "🇹🇷",
        "Turkmenistan": "🇹🇲",
        "Tuvalu": "🇹🇻",
        "Uganda": "🇺🇬",
        "Ukraine": "🇺🇦",
        "United Arab Emirates": "🇦🇪",
        "United Kingdom": "🇬🇧",
        "United States": "🇺🇸",
        "Uruguay": "🇺🇾",
        "Uzbekistan": "🇺🇿",
        "Vanuatu": "🇻🇺",
        "Venezuela": "🇻🇪",
        "Vietnam": "🇻🇳",
        "Yemen": "🇾🇪",
        "Zambia": "🇿🇲",
        "Zimbabwe": "🇿🇼",
    };
    // Check if the region is in the mapping; otherwise, return a default emoji
    return flagMap[region] || "🌎"; // Default to a globe emoji if region is not found
}

const countries = [
        { name: "United States", results: 0, lat: 37.0902, lng: -95.7129 },
        { name: "Canada", results: 0, lat: 56.1304, lng: -106.3468 },
        { name: "Turkey", results: 0, lat: 38.9637, lng: 35.2433 },
        { name: "Türkiye", results: 0, lat: 38.9637, lng: 35.2433 },
        { name: "Afghanistan", results: 0, lat: 33.93911, lng: 67.709953 },
        { name: "Albania", results: 0, lat: 41.153332, lng: 20.168331 },
        { name: "Algeria", results: 0, lat: 28.033886, lng: 1.659626 },
        { name: "Andorra", results: 0, lat: 42.546245, lng: 1.601554 },
        { name: "Angola", results: 0, lat: -11.202692, lng: 17.873887 },
        { name: "Antigua and Barbuda", results: 0, lat: 17.060816, lng: -61.796428 },
        { name: "Argentina", results: 0, lat: -38.416097, lng: -63.616672 },
        { name: "Armenia", results: 0, lat: 40.069099, lng: 45.038189 },
        { name: "Australia", results: 0, lat: -25.274398, lng: 133.775136 },
        { name: "Austria", results: 0, lat: 47.516231, lng: 14.550072 },
        { name: "Azerbaijan", results: 0, lat: 40.143105, lng: 47.576927 },
        { name: "Bahamas", results: 0, lat: 25.03428, lng: -77.39628 },
        { name: "Bahrain", results: 0, lat: 25.930414, lng: 50.637772 },
        { name: "Bangladesh", results: 0, lat: 23.684994, lng: 90.356331 },
        { name: "Barbados", results: 0, lat: 13.193887, lng: -59.543198 },
        { name: "Belarus", results: 0, lat: 53.709807, lng: 27.953389 },
        { name: "Belgium", results: 0, lat: 50.85034, lng: 4.35171 },
        { name: "Belize", results: 0, lat: 17.189877, lng: -88.49765 },
        { name: "Benin", results: 0, lat: 9.30769, lng: 2.315834 },
        { name: "Bhutan", results: 0, lat: 27.514162, lng: 90.433601 },
        { name: "Bolivia", results: 0, lat: -16.290154, lng: -63.588653 },
        { name: "Bosnia and Herzegovina", results: 1, lat: 43.915886, lng: 17.679076 },
        { name: "Botswana", results: 0, lat: -22.328474, lng: 24.684866 },
        { name: "Brazil", results: 0, lat: -14.235004, lng: -51.92528 },
        { name: "Brunei", results: 0, lat: 4.535277, lng: 114.727669 },
        { name: "Bulgaria", results: 0, lat: 42.733883, lng: 25.48583 },
        { name: "Burkina Faso", results: 0, lat: 12.238333, lng: -1.561593 },
        { name: "Burundi", results: 0, lat: -3.373056, lng: 29.918886 },
        { name: "Cabo Verde", results: 0, lat: 16.5388, lng: -23.0418 },
        { name: "Cambodia", results: 0, lat: 12.565679, lng: 104.990963 },
        { name: "Cameroon", results: 0, lat: 7.369722, lng: 12.354722 },
        { name: "Central African Republic", results: 1, lat: 6.611111, lng: 20.939444 },
        { name: "Chad", results: 0, lat: 15.454166, lng: 18.732207 },
        { name: "Chile", results: 0, lat: -35.675147, lng: -71.542969 },
        { name: "China", results: 0, lat: 35.86166, lng: 104.195397 },
        { name: "Colombia", results: 0, lat: 4.570868, lng: -74.297333 },
        { name: "Comoros", results: 0, lat: -11.875001, lng: 43.872219 },
        { name: "Congo (Congo-Brazzaville)", results: 0, lat: -0.228021, lng: 15.827659 },
        { name: "Costa Rica", results: 0, lat: 9.748917, lng: -83.753428 },
        { name: "Croatia", results: 0, lat: 45.1, lng: 15.2 },
        { name: "Cuba", results: 0, lat: 21.521757, lng: -77.781167 },
        { name: "Cyprus", results: 0, lat: 35.126413, lng: 33.429859 },
        { name: "Czechia (Czech Republic)", results: 0, lat: 49.817492, lng: 15.472962 },
        { name: "Democratic Republic of the Congo (Congo-Kinshasa)", results: 1, lat: -4.038333, lng: 21.758664 },
        { name: "Denmark", results: 0, lat: 56.26392, lng: 9.501785 },
        { name: "Djibouti", results: 0, lat: 11.825138, lng: 42.590275 },
        { name: "Dominica", results: 0, lat: 15.414999, lng: -61.370976 },
        { name: "Dominican Republic", results: 1, lat: 18.735693, lng: -70.162651 },
        { name: "Ecuador", results: 0, lat: -1.831239, lng: -78.183406 },
        { name: "Egypt", results: 0, lat: 26.820553, lng: 30.802498 },
        { name: "El Salvador", results: 0, lat: 13.794185, lng: -88.89653 },
        { name: "Equatorial Guinea", results: 1, lat: 1.650801, lng: 10.267895 },
        { name: "Eritrea", results: 0, lat: 15.179384, lng: 39.782334 },
        { name: "Estonia", results: 0, lat: 58.595272, lng: 25.013607 },
        { name: "Eswatini (fmr. Swaziland)", results: 0, lat: -26.522503, lng: 31.465866 },
        { name: "Ethiopia", results: 0, lat: 9.145, lng: 40.489673 },
        { name: "Fiji", results: 0, lat: -16.578193, lng: 179.414413 },
        { name: "Finland", results: 0, lat: 61.92411, lng: 25.748151 },
        { name: "France", results: 0, lat: 46.603354, lng: 1.888334 },
        { name: "Gabon", results: 0, lat: -0.803689, lng: 11.609444 },
        { name: "Gambia", results: 0, lat: 13.443182, lng: -15.310139 },
        { name: "Georgia", results: 0, lat: 42.315407, lng: 43.356892 },
        { name: "Germany", results: 0, lat: 51.165691, lng: 10.451526 },
        { name: "Ghana", results: 0, lat: 7.260092, lng: -0.820789 },
        { name: "Greece", results: 0, lat: 39.074208, lng: 21.824312 },
        { name: "Grenada", results: 0, lat: 12.262776, lng: -61.604171 },
        { name: "Guatemala", results: 0, lat: 15.783471, lng: -90.230759 },
        { name: "Guinea", results: 0, lat: 9.945587, lng: -9.696645 },
        { name: "Guinea-Bissau", results: 1, lat: 11.803749, lng: -15.180413 },
        { name: "Guyana", results: 0, lat: 4.860416, lng: -58.93018 },
        { name: "Haiti", results: 0, lat: 18.971187, lng: -72.285215 },
        { name: "Holy See", results: 0, lat: 41.902916, lng: 12.453389 },
        { name: "Honduras", results: 0, lat: 15.199999, lng: -86.241905 },
        { name: "Hungary", results: 0, lat: 47.162494, lng: 19.503304 },
        { name: "Iceland", results: 0, lat: 64.963051, lng: -19.020835 },
        { name: "India", results: 0, lat: 20.593684, lng: 78.96288 },
        { name: "Indonesia", results: 0, lat: -0.789275, lng: 113.921327 },
        { name: "Iran", results: 0, lat: 32.427908, lng: 53.688046 },
        { name: "Iraq", results: 0, lat: 33.223191, lng: 43.679291 },
        { name: "Ireland", results: 0, lat: 53.41291, lng: -8.24389 },
        { name: "Israel", results: 0, lat: 31.046051, lng: 34.851612 },
        { name: "Italy", results: 0, lat: 41.87194, lng: 12.56738 },
        { name: "Ivory Coast", results: 0, lat: 7.539989, lng: -5.54708 },
        { name: "Jamaica", results: 0, lat: 18.109581, lng: -77.297508 },
        { name: "Japan", results: 0, lat: 36.204824, lng: 138.252924 },
        { name: "Jordan", results: 0, lat: 30.585164, lng: 36.238414 },
        { name: "Kazakhstan", results: 0, lat: 48.019573, lng: 66.923684 },
        { name: "Kenya", results: 0, lat: -1.292066, lng: 36.821946 },
        { name: "Kiribati", results: 0, lat: -3.370417, lng: -168.734039 },
        { name: "Kuwait", results: 0, lat: 29.375859, lng: 47.977405 },
        { name: "Kyrgyzstan", results: 0, lat: 41.20438, lng: 74.766098 },
        { name: "Laos", results: 0, lat: 19.85627, lng: 102.495496 },
        { name: "Latvia", results: 0, lat: 56.879635, lng: 24.603189 },
        { name: "Lebanon", results: 0, lat: 33.854721, lng: 35.862285 },
        { name: "Lesotho", results: 0, lat: -29.609988, lng: 28.233608 },
        { name: "Liberia", results: 0, lat: 6.428055, lng: -9.429499 },
        { name: "Libya", results: 0, lat: 26.3351, lng: 17.228331 },
        { name: "Liechtenstein", results: 0, lat: 47.166, lng: 9.555373 },
        { name: "Lithuania", results: 0, lat: 55.169438, lng: 23.881275 },
        { name: "Luxembourg", results: 0, lat: 49.815273, lng: 6.129583 },
        { name: "Madagascar", results: 0, lat: -18.766947, lng: 46.869107 },
        { name: "Malawi", results: 0, lat: -13.254308, lng: 34.301525 },
        { name: "Malaysia", results: 0, lat: 4.210484, lng: 101.975766 },
        { name: "Maldives", results: 0, lat: 3.202778, lng: 73.22068 },
        { name: "Mali", results: 0, lat: 17.570692, lng: -3.996166 },
        { name: "Malta", results: 0, lat: 35.937496, lng: 14.375416 },
        { name: "Marshall Islands", results: 0, lat: 7.131474, lng: 171.184478 },
        { name: "Mauritania", results: 0, lat: 21.00789, lng: -10.940835 },
        { name: "Mauritius", results: 0, lat: -20.348404, lng: 57.552152 },
        { name: "Mexico", results: 0, lat: 23.634501, lng: -102.552784 },
        { name: "Micronesia", results: 0, lat: 7.425554, lng: 150.550812 },
        { name: "Moldova", results: 0, lat: 47.411631, lng: 28.369885 },
        { name: "Monaco", results: 0, lat: 43.750298, lng: 7.412841 },
        { name: "Mongolia", results: 0, lat: 46.862496, lng: 103.846656 },
        { name: "Montenegro", results: 0, lat: 42.708678, lng: 19.37439 },
        { name: "Morocco", results: 0, lat: 31.791702, lng: -7.09262 },
        { name: "Mozambique", results: 0, lat: -18.665695, lng: 35.529562 },
        { name: "Myanmar (formerly Burma)", results: 1, lat: 21.913965, lng: 95.956223 },
        { name: "Namibia", results: 0, lat: -22.95764, lng: 18.49041 },
        { name: "Nauru", results: 0, lat: -0.522778, lng: 166.931503 },
        { name: "Nepal", results: 0, lat: 28.394857, lng: 84.124008 },
        { name: "Netherlands", results: 0, lat: 52.132633, lng: 5.291266 },
        { name: "New Zealand", results: 0, lat: -40.900557, lng: 174.885971 },
        { name: "Nicaragua", results: 0, lat: 12.865416, lng: -85.207229 },
        { name: "Niger", results: 0, lat: 17.607789, lng: 8.081666 },
        { name: "Nigeria", results: 0, lat: 9.082, lng: 8.675277 },
        { name: "North Korea", results: 0, lat: 40.339852, lng: 127.510093 },
        { name: "North Macedonia (formerly Macedonia)", results: 0, lat: 41.608635, lng: 21.745275 },
        { name: "Norway", results: 0, lat: 60.472024, lng: 8.468946 },
        { name: "Oman", results: 0, lat: 21.512583, lng: 55.923255 },
        { name: "Pakistan", results: 0, lat: 30.375321, lng: 69.345116 },
        { name: "Palau", results: 0, lat: 7.51498, lng: 134.58252 },
        { name: "Palestine State", results: 0, lat: 31.952162, lng: 35.233154 },
        { name: "Panama", results: 0, lat: 8.537981, lng: -80.782127 },
        { name: "Papua New Guinea", results: 0, lat: -6.314993, lng: 143.95555 },
        { name: "Paraguay", results: 0, lat: -23.442503, lng: -58.443832 },
        { name: "Peru", results: 0, lat: -9.190347, lng: -75.015152 },
        { name: "Philippines", results: 0, lat: 12.879721, lng: 121.774017 },
        { name: "Poland", results: 0, lat: 51.919438, lng: 19.145136 },
        { name: "Portugal", results: 0, lat: 39.399872, lng: -8.224454 },
        { name: "Qatar", results: 0, lat: 25.354826, lng: 51.183884 },
        { name: "Romania", results: 0, lat: 45.943161, lng: 24.96676 },
        { name: "Russia", results: 0, lat: 61.52401, lng: 105.318756 },
        { name: "Rwanda", results: 0, lat: -1.940278, lng: 29.873888 },
        { name: "Saint Kitts and Nevis", results: 0, lat: 17.357822, lng: -62.782998 },
        { name: "Saint Lucia", results: 0, lat: 13.909444, lng: -60.978893 },
        { name: "Saint Vincent and the Grenadines", results: 0, lat: 12.984305, lng: -61.287228 },
        { name: "Samoa", results: 0, lat: -13.759029, lng: -172.104629 },
        { name: "San Marino", results: 0, lat: 43.94236, lng: 12.457777 },
        { name: "Sao Tome and Principe", results: 0, lat: 0.18636, lng: 6.613081 },
        { name: "Saudi Arabia", results: 0, lat: 23.885942, lng: 45.079162 },
        { name: "Senegal", results: 0, lat: 14.497401, lng: -14.452362 },
        { name: "Serbia", results: 0, lat: 44.016521, lng: 21.005859 },
        { name: "Seychelles", results: 0, lat: -4.679574, lng: 55.491977 },
        { name: "Sierra Leone", results: 0, lat: 8.460555, lng: -11.779889 },
        { name: "Singapore", results: 0, lat: 1.352083, lng: 103.819836 },
        { name: "Slovakia", results: 0, lat: 48.669026, lng: 19.699024 },
        { name: "Slovenia", results: 0, lat: 46.151241, lng: 14.995463 },
        { name: "Solomon Islands", results: 0, lat: -9.64571, lng: 160.156194 },
        { name: "Somalia", results: 0, lat: 5.152149, lng: 46.199616 },
        { name: "South Africa", results: 0, lat: -30.559482, lng: 22.937506 },
        { name: "South Korea", results: 0, lat: 35.907757, lng: 127.766922 },
        { name: "South Sudan", results: 0, lat: 6.877, lng: 31.307 },
        { name: "Spain", results: 0, lat: 40.463667, lng: -3.74922 },
        { name: "Sri Lanka", results: 0, lat: 7.873054, lng: 80.771797 },
        { name: "Sudan", results: 0, lat: 12.862807, lng: 30.217636 },
        { name: "Suriname", results: 0, lat: 3.919305, lng: -56.027783 },
        { name: "Sweden", results: 0, lat: 60.128161, lng: 18.643501 },
        { name: "Switzerland", results: 0, lat: 46.818188, lng: 8.227512 },
        { name: "Syria", results: 0, lat: 34.802075, lng: 38.996815 },
        { name: "Tajikistan", results: 0, lat: 38.861034, lng: 71.276093 },
        { name: "Tanzania", results: 0, lat: -6.369028, lng: 34.888822 },
        { name: "Thailand", results: 0, lat: 15.870032, lng: 100.992541 },
        { name: "Timor-Leste", results: 0, lat: -8.874217, lng: 125.727539 },
        { name: "Togo", results: 0, lat: 8.619543, lng: 0.824782 },
        { name: "Tonga", results: 0, lat: -21.178986, lng: -175.198242 },
        { name: "Trinidad and Tobago", results: 0, lat: 10.691803, lng: -61.222503 },
        { name: "Tunisia", results: 0, lat: 33.886917, lng: 9.537499 },
        { name: "Turkey", results: 0, lat: 38.963745, lng: 35.243322 },
        { name: "Turkmenistan", results: 1, lat: 38.969719, lng: 59.556278 },
        { name: "Tuvalu", results: 0, lat: -7.109535, lng: 177.64933 },
        { name: "Uganda", results: 0, lat: 1.373333, lng: 32.290275 },
        { name: "Ukraine", results: 0, lat: 48.379433, lng: 31.16558 },
        { name: "United Arab Emirates", results: 1, lat: 23.424076, lng: 53.847818 },
        { name: "United Kingdom", results: 0, lat: 55.378051, lng: -3.435973 },
        { name: "Uruguay", results: 0, lat: -32.522779, lng: -55.765835 },
        { name: "Uzbekistan", results: 0, lat: 41.377491, lng: 64.585262 },
        { name: "Vanuatu", results: 0, lat: -15.376706, lng: 166.959158 },
        { name: "Venezuela", results: 0, lat: 6.42375, lng: -66.58973 },
        { name: "Vietnam", results: 0, lat: 14.058324, lng: 108.277199 },
        { name: "Yemen", results: 0, lat: 15.552727, lng: 48.516388 },
        { name: "Zambia", results: 0, lat: -13.133897, lng: 27.849332 },
        { name: "Zimbabwe", results: 0, lat: -19.015438, lng: 29.154857 },
];

// Function to load country flags and count the results for each country
function cargarBanderasPaises(datos) {
    var countryFlagsList = document.getElementById("countryFlags");
    var countryCounts = {}; // Objeto para contar la cantidad de resultados por país

    // Inicializar el conteo en 0 para cada país
    countries.forEach(function (country) {
        countryCounts[country] = 0;
    });

    // Contar la cantidad de resultados para cada país
    datos.forEach(function (resultado) {
        var country = resultado["Región"];
        if (country in countryCounts) {
            countryCounts[country]++;
        }
    });

    // Mostrar las banderas y la cantidad de resultados para cada país
    countries.forEach(function (country) {
        var listItem = document.createElement("li");
        var flag = getFlagEmoji(country);
        var count = countryCounts[country];
        listItem.innerHTML = flag + " " + country + ": " + count + " resultados";
        countryFlagsList.appendChild(listItem);
    });
}

// Llamar a la función para cargar banderas y contar resultados cuando la página carga los datos
cargarDatos(function (datos) {
    cargarBanderasPaises(datos);
});


function filtrarResultados() {
    cargarDatos(function (datos) {
        var puertoSeleccionado = document.getElementById("puertoFilter").value;
        var servicioSeleccionado = document.getElementById("servicioFilter").value;
        var busquedaTexto = document.getElementById("busqueda").value.toLowerCase();

        var busquedaCondiciones = busquedaTexto.split('&&').map(function (condition) {
            return condition.trim();
        });

        var resultadosFiltrados = datos.filter(function (resultado) {
            var coincidePuerto = puertoSeleccionado === "" || resultado.Puerto.toString() === puertoSeleccionado;
            var coincideServicio = servicioSeleccionado === "" || resultado.Servicio === servicioSeleccionado;

            var cumpleTodasLasCondiciones = busquedaCondiciones.every(function (condicion) {
                if (condicion.includes('||')) {
                    var condicionesOR = condicion.split('||').map(function (condition) {
                        return condition.trim();
                    });

                    return condicionesOR.some(function (condition) {
                        return condition === "" || Object.values(resultado).some(function (campo) {
                            if (campo && typeof campo === "string") {
                                return campo.toLowerCase().includes(condition);
                            }
                            return false;
                        });
                    });
                } else {
                    if (condicion.startsWith('!')) {
                        condicion = condicion.substring(1).trim();
                        return !Object.values(resultado).some(function (campo) {
                            if (campo && typeof campo === "string") {
                                return campo.toLowerCase().includes(condicion);
                            }
                            return false;
                        });
                    } else if (condicion.includes('>')) {
                        var parts = condicion.split('>');
                        var field = parts[0].trim();
                        var value = parseFloat(parts[1].trim());
                        if (!isNaN(value) && resultado[field] > value) {
                            return true;
                        }
                    } else if (condicion.includes('<')) {
                        var parts = condicion.split('<');
                        var field = parts[0].trim();
                        var value = parseFloat(parts[1].trim());
                        if (!isNaN(value) && resultado[field] < value) {
                            return true;
                        }
                    } else {
                        return condicion === "" || Object.values(resultado).some(function (campo) {
                            if (campo && typeof campo === "string") {
                                return campo.toLowerCase().includes(condicion);
                            }
                            return false;
                        });
                    }
                }
            });

            return coincidePuerto && coincideServicio && cumpleTodasLasCondiciones;
        });

        var listaResultados = document.getElementById("resultados");
        listaResultados.innerHTML = "";

        if (resultadosFiltrados.length === 0) {
            var notFoundImageContainer = document.createElement("div");
            notFoundImageContainer.classList.add("not-found-image-container");

            var image = document.createElement("img");
            image.src = "404.png";
            image.width = 750;
            image.alt = "Not Found";
            image.classList.add("not-found-image");

            notFoundImageContainer.appendChild(image);
            listaResultados.appendChild(notFoundImageContainer);
            enviarPalabraBusquedaAlServidor(busquedaTexto);
        } else {
            mostrarResultados(resultadosFiltrados);
        }
    });
}

function enviarPalabraBusquedaAlServidor(palabraBusqueda) {
    fetch('/debugger', {
        method: 'POST',
        body: JSON.stringify({ palabraBusqueda: palabraBusqueda }),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                console.log('Palabra de búsqueda enviada al servidor debugger.');
            } else {
                console.error('Error al enviar la palabra de búsqueda al servidor debugger.');
            }
        })
        .catch(function (error) {
            console.error('Error de red al enviar la palabra de búsqueda al servidor debugger:', error);
        });
}

var currentPage = 1;
var resultsPerPage = 10;
var totalResults = 0;
var resultados = [];

function mostrarResultados(resultados) {
    var listaResultados = document.getElementById("resultados");

    var resultadosUnicosPorIP = [];
    var ips = new Set();

    resultados.forEach(function (resultado) {
        if (!ips.has(resultado.IP)) {
            ips.add(resultado.IP);
            resultadosUnicosPorIP.push(resultado);
        }
    });

    this.resultados = resultadosUnicosPorIP;
    this.totalResults = resultadosUnicosPorIP.length;

    var startIndex = (currentPage - 1) * resultsPerPage;
    var endIndex = startIndex + resultsPerPage;

    var resultsToDisplay = resultadosUnicosPorIP.slice(startIndex, endIndex);

    listaResultados.innerHTML = "";

    resultsToDisplay.forEach(function (resultado) {
        var item = document.createElement("li");
        item.classList.add("result-item");

        var checkboxContainer = document.createElement("label");
        checkboxContainer.classList.add("checkbox-container");

        var checkboxInput = document.createElement("input");
        checkboxInput.setAttribute("type", "checkbox");
        item.appendChild(checkboxInput);
        checkboxInput.addEventListener("click", function () {
            window.open("http://" + resultado.IP + ":" + resultado.Puerto, "_blank");
        });

        var icon = document.createElement("img");
        icon.setAttribute("src", "icon.png");
        icon.classList.add("icon");

        checkboxContainer.appendChild(icon);
        checkboxContainer.appendChild(checkboxInput);

        item.appendChild(checkboxContainer);
        item.appendChild(checkboxContainer);

        var table = document.createElement("table");
        table.classList.add("result-table");

        var fields = ["IP", "Puerto", "Servicio", "Región", "Banner", "Ciudad", "Dominio", "CredencialesDVR", "SistemaOperativo_RDP", "Fecha", "SistemaOperativo_SMB", "Nombre-PC", "Camara", "Preview"];

        function createImageCell(ip, puerto) {
            var imageCell = document.createElement("td");
            var imagePath = `screenshot/${ip}-${puerto}.png`;

            var img = new Image();
            img.src = imagePath;

            img.onload = function () {
                imageCell.innerHTML = `<div style="text-align: center;"><img src="${imagePath}" alt="Screenshot" style="max-width: 512px;"><p>has_screenshot:true</p></div>`;
                resultado["Preview"] = "has_screenshot:true";
            };

            return imageCell;
        }

        fields.forEach(function (field) {
            var fieldValue = resultado[field];
            if (field === "CredencialesDVR") {
                if (Array.isArray(fieldValue) && fieldValue.length > 0) {
                    var row = table.insertRow();
                    var cell1 = row.insertCell(0);
                    var cell2 = row.insertCell(1);
                    cell1.textContent = field;
                    cell2.textContent = fieldValue.join(', ');
                }
            } else {
                if (((typeof fieldValue === 'string' && fieldValue.trim() !== '') && fieldValue.trim().length !== 1) && fieldValue !== "N/A" && fieldValue !== "NULL" && fieldValue !== "unknown") {
                    var row = table.insertRow();
                    var cell1 = row.insertCell(0);
                    var cell2 = row.insertCell(1);
                    cell1.textContent = field;

                    if (field === "IP") {
                        // Create a row for Port
                        var portRow = table.insertRow();
                        var portCellLabel = portRow.insertCell();
                        portCellLabel.textContent = "Puerto";
                        var portCell = portRow.insertCell();
                        portCell.textContent = resultado.Puerto;
                        const flagEmoji = getFlagEmoji(resultado["Región"]);
                        cell2.textContent = resultado[field] + " " + flagEmoji;
                    } else if (field === "Banner") {
                        cell2.textContent = resultado[field];
                        row.appendChild(createImageCell(resultado["IP"], resultado["Puerto"]));
                    } else {
                        cell2.textContent = fieldValue;
                    }
                }
            }
        });



        var masInfoButton = document.createElement("button");
        masInfoButton.textContent = "Más información";
        masInfoButton.addEventListener("click", function () {
            window.location.href = `detalle.html?ip=${resultado.IP}`;
        });

        item.appendChild(table);
        item.appendChild(masInfoButton);
        listaResultados.appendChild(item);
    });

    updatePaginationControls();
}

// Function to update pagination controls
function updatePaginationControls() {
    var paginationContainer = document.getElementById("pagination");
    paginationContainer.innerHTML = "";

    var totalPages = Math.ceil(totalResults / resultsPerPage);
    var startPage = Math.max(1, currentPage - 5);
    var endPage = Math.min(totalPages, currentPage + 5);

    // Add "Inicio" button
    if (startPage > 1) {
        var startButton = document.createElement("button");
        startButton.textContent = "1";
        startButton.addEventListener("click", function () {
            currentPage = 1;
            mostrarResultados(resultados);
        });
        paginationContainer.appendChild(startButton);
    }

    for (var i = startPage; i <= endPage; i++) {
        var pageButton = document.createElement("button");
        pageButton.textContent = i;
        pageButton.addEventListener("click", function () {
            currentPage = parseInt(this.textContent);
            mostrarResultados(resultados);
        });

        paginationContainer.appendChild(pageButton);
    }

    // Add "Final" button
    if (endPage < totalPages) {
        var finalButton = document.createElement("button");
        finalButton.textContent = totalPages.toString();
        finalButton.addEventListener("click", function () {
            currentPage = totalPages;
            mostrarResultados(resultados);
        });
        paginationContainer.appendChild(finalButton);
    }
}

function loadMoreResults() {
    currentPage++;
    mostrarResultados(resultados);
}

// Function to initiate the script with the search query
function iniciarScriptConBusqueda(searchQuery) {
    showMessage("Actualizando datos..."); // Show a message indicating data update
    var startScriptXhr = new XMLHttpRequest();
    startScriptXhr.onreadystatechange = function () {
        if (startScriptXhr.readyState === 4) {
            if (startScriptXhr.status === 200) {
                showMessage("Script iniciado correctamente."); // Update the success message
            } else {
                showMessage("Error al iniciar el script de Python con la búsqueda.");
            }
        }
    };

    // Modify the URL to pass the searchQuery to the server-side script
    startScriptXhr.open("GET", "/start_script?query=" + encodeURIComponent(searchQuery), true);
    startScriptXhr.send();
}

function extraerIPsFiltradas() {
    var listaResultados = document.getElementById("resultados");
    var items = listaResultados.getElementsByTagName("li");
    var ipsFiltradas = "";
    for (var i = 0; i < items.length; i++) {
        var ipElement = getCellByText(items[i], "IP");
        var puertoElement = getCellByText(items[i], "Puerto");

        if (ipElement && puertoElement) {
            var ipText = ipElement.nextElementSibling.textContent.trim();
            // Extraer solo los números y puntos de la dirección IP
            var ip = ipText.match(/\d+\.\d+\.\d+\.\d+/)[0];
            var puerto = puertoElement.nextElementSibling.textContent.trim();
            ipsFiltradas += ip + ":" + puerto + "\n";
        }
    }
    var blob = new Blob([ipsFiltradas], { type: "text/plain" });
    var enlaceDescarga = document.createElement("a");
    enlaceDescarga.href = URL.createObjectURL(blob);
    enlaceDescarga.download = "ips_extraidas.txt";
    enlaceDescarga.click();
}

function getCellByText(item, text) {
    var cells = item.getElementsByTagName("td");
    for (var i = 0; i < cells.length; i++) {
        if (cells[i].textContent.trim() === text) {
            return cells[i];
        }
    }
    return null;
}





// Show all results when the page loads
cargarDatos(function (datos) {
    mostrarResultados(datos);
});

// Function to toggle dark mode
function toggleDarkMode() {
    const mainContainer = document.getElementById("main-container");
    const mainContainerr = document.getElementById("servicioFilter");
    mainContainer.classList.toggle('dark-mode'); // Add or remove the 'dark-mode' class to the main container
    mainContainerr.classList.toggle('dark-mode'); // Add or remove the 'dark-mode' class to the main container

    // You can also add style change for the filter options box here
    const puertoFilter = document.getElementById("puertoFilter");
    puertoFilter.classList.toggle('dark-mode-select'); // Add or remove the 'dark-mode-select' class to the filter options box

    // You can add more logic here to save the user's preference in a cookie or localStorage
}

// Function to load country flags and count the results for each country
function cargarBanderasPaises(datos) {
    var countryCounts = {}; // Object to count the number of results per country

    // Initialize the count to 0 for each country
    countries.forEach(function (country) {
        countryCounts[country.name] = 0;
    });

    // Count the number of results for each country
    datos.forEach(function (resultado) {
        var countryName = resultado["Región"]; // Make sure "Región" is the correct property
        var country = countries.find(c => c.name === countryName); // Find the country by name
        if (country) {
            countryCounts[country.name]++; // Increment the country's results count
        }
    });

    return countryCounts; // Return the count results
}


function mapa(datos) {
    const countryCounts = cargarBanderasPaises(datos);

    // Update the 'results' values in the 'countries' array
    countries.forEach(function (country) {
        country.results = countryCounts[country.name];
    });

    // Create a map and center it at an initial location
    var map = L.map('map').setView([0, 0], 2);

    // Add an OpenStreetMap base map layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    // Iterate through the data and add red markers for countries with results
    countries.forEach(function (data) {
        if (data.results > 0) {
            var redIcon = new L.Icon({
                iconUrl: 'marcar.png',
                iconSize: [25, 20],
                iconAnchor: [22, 22],
                popupAnchor: [1, -34],
            });

            L.marker([data.lat, data.lng], { icon: redIcon })
                .addTo(map)
                .bindPopup(data.name + "<br>" + data.results + " resultados");
        }
    });
}

// Call the function to display results and update the 'countries' array
cargarDatos(function (datos) {
    mapa(datos);
});

// Function to toggle dark mode
function toggleDarkMode() {
    const mainContainer = document.getElementById("main-container");
    const mainContainerr = document.getElementById("servicioFilter");
    mainContainer.classList.toggle('dark-mode'); // Add or remove the 'dark-mode' class to the main container
    mainContainerr.classList.toggle('dark-mode'); // Add or remove the 'dark-mode' class to the main container

    // You can also add style change for the filter options box here
    const puertoFilter = document.getElementById("puertoFilter");
    puertoFilter.classList.toggle('dark-mode-select'); // Add or remove the 'dark-mode-select' class to the filter options box

    // You can add more logic here to save the user's preference in a cookie or localStorage
}

// Display all results when the page loads
cargarDatos(function (datos) {
    mostrarResultados(datos);
});
