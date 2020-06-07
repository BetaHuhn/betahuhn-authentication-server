//main.js - fck-afd URL shortener - Maximilian Schiller
const input = document.getElementById('url-input'),
    input2 = document.getElementById('url-input2'),
    out = document.getElementById('out'),
    start = document.getElementById('start')

/* Darkmode Support */
const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
const switchText = document.getElementById('switchText');
detectDarkMode()

async function confirm() {
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ passwd: input.value, passwd2: input2.value })
    };
    const response = await fetch('/auth/new-password', options);
    const json = await response.json();
    if (json.status == 400) {
        out.innerHTML = `<h1>Your token has expired</h1>`;
    } else if (json.status == 200) {
        console.log(json);
        out.innerHTML = `<h1>Your password was successfully saved</h1>`;
        delete_cookie("token", "/", ".betahuhn.de")
        setTimeout(function() { window.location.href = "https://auth.betahuhn.de"; }, 1000);
    } else if (json.status == 404) {
        console.log(json);
        out.innerHTML = `<h1>Your password can't contain spaces</h1>`;
    } else if (json.status == 405) {
        console.log(json);
        out.innerHTML = `<h1>Your Password is too long (max. 20)</h1>`;
    } else if (json.status == 406) {
        console.log(json);
        out.innerHTML = `<h1>Your Password is too short (min. 8)</h1>`;
    } else if (json.status == 401) {
        console.log(json);
        out.innerHTML = `<h1>Passwords don't match</h1>`;
    } else if (json.status == 402) {
        console.log(json);
        out.innerHTML = `<h1>Your new password can't match old one</h1>`;
    } else {
        out.innerHTML = `<h1>An error occurred: ${json.status}</h1>`;

    }
}


function delete_cookie(name, path, domain) {
    if (getCookie(name)) {
        document.cookie = name + "=" +
            ((path) ? ";path=" + path : "") +
            ((domain) ? ";domain=" + domain : "") +
            ";expires=Thu, 01 Jan 1970 00:00:01 GMT";
    }
}

function getCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

/* Dark Mode switch logic */

//Gets a cookie by key
function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return undefined;
}

//Switch theme when slider changes
function switchThemeSlider() {
    if (toggleSwitch.checked) {
        document.documentElement.setAttribute('data-theme', 'dark');
        switchText.innerHTML = "Dark Mode"
        document.cookie = "darkmode=true;path=/;domain=betahuhn.de";
    } else {
        document.documentElement.setAttribute('data-theme', 'light');
        switchText.innerHTML = "Light Mode"
        document.cookie = "darkmode=false;path=/;domain=betahuhn.de";
    }
}

//Switch between light and dark theme
function switchTheme() {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.setAttribute('data-theme', 'dark');
        switchText.innerHTML = "Dark Mode"
        toggleSwitch.checked = true;
        document.cookie = "darkmode=true;path=/;domain=betahuhn.de";
        console.log("Cookie: " + getCookie('darkmode'))
    } else {
        document.documentElement.setAttribute('data-theme', 'light');
        switchText.innerHTML = "Light Mode"
        toggleSwitch.checked = false;
        document.cookie = "darkmode=false;path=/;domain=betahuhn.de";
        console.log("Cookie: " + getCookie('darkmode'))
    }
}

//Runs in the beginning. Checks if System Dark mode is on or if preference set in cookie
function detectDarkMode() {
    console.log("Cookie: " + getCookie('darkmode'))
    if (getCookie('darkmode') == 'false') {
        console.log("Switching to the light side")
        document.documentElement.setAttribute('data-theme', 'light');
        switchText.innerHTML = "Light Mode";
        toggleSwitch.checked = false;
        document.cookie = "darkmode=false;path=/;domain=betahuhn.de";
    } else if (getCookie('darkmode') == 'true') {
        console.log("Switching to the dark side")
        document.documentElement.setAttribute('data-theme', 'dark');
        switchText.innerHTML = "Dark Mode";
        toggleSwitch.checked = true;
        document.cookie = "darkmode=true;path=/;domain=betahuhn.de";
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        console.log("Switching to the dark side")
        document.documentElement.setAttribute('data-theme', 'dark');
        switchText.innerHTML = "Dark Mode";
        toggleSwitch.checked = true;
        document.cookie = "darkmode=true;path=/;domain=betahuhn.de";
    } else {
        console.log("Switching to the light side")
        document.documentElement.setAttribute('data-theme', 'light');
        switchText.innerHTML = "Light Mode";
        toggleSwitch.checked = false;
        document.cookie = "darkmode=false;path=/;domain=betahuhn.de";
    }
    window.matchMedia("(prefers-color-scheme: dark)").addListener(e => e.matches && switchTheme())
    window.matchMedia("(prefers-color-scheme: light)").addListener(e => e.matches && switchTheme())
    toggleSwitch.addEventListener('change', switchThemeSlider, false);
}