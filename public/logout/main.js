const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    error = document.getElementById('error')

/* Darkmode Support */
const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
const switchText = document.getElementById('switchText');
detectDarkMode()

async function logout() {
    var url_string = window.location.href
    var url = new URL(url_string);
    var ref = url.searchParams.get("ref");
    var all = url.searchParams.get("all");
    if (all == undefined) {
        all = false;
    }
    if (ref == undefined) {
        var path = '/auth/logout?all=' + all;
    } else {
        var path = '/auth/logout?ref=' + ref + '&all=' + all;
    }
    const options = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        },
    };
    const response = await fetch(path, options);
    const json = await response.json();
    delete_cookie("access_token", "/", ".betahuhn.de")
    delete_cookie("refresh_token", "/", ".betahuhn.de")
    window.location.replace(json.ref);
}

function delete_cookie(name, path, domain) {
    if (getCookie(name)) {
        document.cookie = name + "=" +
            ((path) ? ";path=" + path : "") +
            ((domain) ? ";domain=" + domain : "") +
            ";expires=Thu, 01 Jan 1970 00:00:01 GMT";
    }
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