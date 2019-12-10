//main.js - fck-afd URL shortener - Maximilian Schiller
var input = document.getElementById('url-input'),
      out = document.getElementById('out'),
      start = document.getElementById('start'),
      header = document.getElementById('header')

async function auth(){
    input = document.getElementById('url-input')
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({email: input.value})
    };
    const response = await fetch('/api/reset-password/auth', options);
    const json = await response.json();
    if (json.status == 400){
      start.innerHTML = `<h1>Diese Email-Adresse existiert nicht</h1>`;
    }else if (json.status == 200){
      console.log(json);
      header.removeChild(header.childNodes[0]);
      start.innerHTML = `<h1>Bist du sicher das du \ndein Passwort zurücksetzen\nwillst? Wir schicken dir\neine Reset-Email an:\n ${json.email}</h1>`;
      out.innerHTML = `<button class="btn btn--primary uppercase" onclick="confirm()">Zurücksetzen</button>`;
    }
    else{
      start.innerHTML = `<h1>Es ist ein Fehler aufgetreten: ${json.status}</h1>`;
    }
}

async function run(){
    header.innerHTML = `<h1>Um dein Passwort zurück zu \nsetzen musst du zuerst deine \nEmail-Adresse eingeben:</h1>`;
    start.innerHTML = `<input type="text" id="url-input" class="form__field" placeholder="Email">`;
    out.innerHTML = `<button class="btn btn--primary uppercase" onclick="auth()">Check</button>`;
}

async function confirm(){
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({confirm: true})
  };
  const response = await fetch('/api/reset-password', options);
  const json = await response.json();
  if (json.status == 400){
    window.location.href = "https://auth.betahuhn.de/login?ref=auth.betahuhn.de/reset-password";
  }else if (json.status == 200){
    console.log(json);
    start.innerHTML = `<h1>Bitte überprüfe dein \nEmail Postfach:\n ${json.email}</h1>`;
    out.innerHTML = `<a class="bottom" href="/"><button class="btn btn--primary uppercase">Home</button></a>`;
  }
  else{
    start.innerHTML = `<h1>Es ist ein Fehler aufgetreten. Wir konnten dein Passwort \nnicht zurücksetzen. Bitte probiere es erneut.</h1>`;
    out.innerHTML = `<button id="shorten-button" class="btn btn--primary uppercase" onclick="/reset-password">Zurück</button>`;
    
  }
}














