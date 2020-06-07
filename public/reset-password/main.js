//main.js - fck-afd URL shortener - Maximilian Schiller
var input = document.getElementById('url-input'),
    out = document.getElementById('out'),
    start = document.getElementById('start'),
    header = document.getElementById('header')

var email;

/* Darkmode Support */
const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
const switchText = document.getElementById('switchText');
detectDarkMode()

async function auth() {
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email })
    };
    const response = await fetch('/auth/reset-password', options);
    const json = await response.json();
    if (json.status == 200) {
        console.log(json);
        start.innerHTML = `<h1>Please check your mailbox: ${json.email}</h1>`;
        out.innerHTML = `<a class="bottom" href="/login"><button class="btn btn--primary uppercase">Login</button></a>`;
    } else if (json.status == 405) {
        start.innerHTML = `<h1>Email Address doesn't exist</h1>`;
    } else {
        start.innerHTML = `<h1>An error occurred: ${json.status}</h1>`;
    }
}

async function run() {
    header.innerHTML = `<h1>Enter email to reset password</h1>`;
    start.innerHTML = `<input type="text" id="url-input" class="form__field" placeholder="Email">`;
    out.innerHTML = `<button class="btn btn--primary uppercase" onclick="confirm()">Check</button>`;
}

function confirm() {
    email = document.getElementById('url-input').value;
    header.removeChild(header.childNodes[0]);
    start.innerHTML = `<h1>Are you sure you want to reset your password? \nIf yes, we will send an email to: ${email}</h1>`;
    out.innerHTML = `<button class="btn btn--primary uppercase" onclick="auth()">Reset</button>`;
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