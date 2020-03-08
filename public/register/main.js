const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    name = document.getElementById('name-input'),
    error = document.getElementById('error')

/* Darkmode Support */
const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
const switchText = document.getElementById('switchText');
detectDarkMode()

async function register() {
    const data = {
        email: email.value,
        password: passwd.value,
        name: name.value
    };
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    };
    const response = await fetch('/auth/register', options);
    const json = await response.json();
    if (json.status == 400) {
        error.innerHTML = `<p id=text >Email not valid</p>`;
    } else if (json.status == 407) {
        error.innerHTML = `<p id=text >Email already in use</p>`;
    } else if (json.status == 404) {
        error.innerHTML = `<p id=text >Password has whitespace</p>`;
    } else if (json.status == 405) {
        error.innerHTML = `<p id=text >Password too long (max. 20)</p>`;
    } else if (json.status == 406) {
        error.innerHTML = `<p id=text >Password too short (min. 8)</p>`;
    } else if (json.status == 401) {
        error.innerHTML = `<p id=text >Password not valid. (Only A-z 0-9 !?)</p>`;
    } else if (json.status == 408) {
        error.innerHTML = `<p id=text >Please fill out every field!</p>`;
    } else if (json.status == 200) {
        console.log("registration success");
        var element = document.getElementById("registerForm");
        element.parentNode.removeChild(element);

        document.getElementById("heading").innerHTML = "Success"

        error.innerHTML = `<p id=text >Please verify your account by clicking on the link send to your email address</p>`;
        //window.location.replace("/");
    } else {
        error.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
    }
}

passwd.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        event.preventDefault();
        document.getElementById("register-button").click();
    }
});

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

//Add System Darkmode listener
var darkModeMatcher = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");

function onDarkModeChange(callback) {
    if (!darkModeMatcher) {
        return;
    }
    darkModeMatcher.addListener(({ matches }) => callback(matches));
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
    onDarkModeChange(switchTheme)
    toggleSwitch.addEventListener('change', switchThemeSlider, false);
}