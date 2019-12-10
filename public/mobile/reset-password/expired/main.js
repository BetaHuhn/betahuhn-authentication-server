//main.js - fck-afd URL shortener - Maximilian Schiller
var input = document.getElementById('url-input'),
      out = document.getElementById('out'),
      button = document.getElementById('button'),
      header = document.getElementById('header')


async function run(){
    const urlParams = new URLSearchParams(window.location.search);
    const reason = urlParams.get('reason');
    console.log(reason)
    if(reason == "expired"){
      out.innerHTML = `<h1>Dein Token ist abgelaufen.\nUm dein Passwort zurück\nzu setzen musst du\nerneut anfragen.</h1>`;
      button.innerHTML = `<a class="bottom" href="/reset-password"><button class="btn btn--primary uppercase">Anfragen</button></a>`;
    }else if(reason == "not-valid"){
      out.innerHTML = `<h1>Dein Token ist nicht Valide.\nBitte versuche es erneut.</h1>`;
      button.innerHTML = `<a class="bottom" href="/login?ref=auth.betahuhn.de/new-password"><button class="btn btn--primary uppercase">Retry</button></a>`;
    }else if(reason == "logout"){
      out.innerHTML = `<h1>Du wurdest automatisch ausgeloggt.\nUm dein Passwort zu ändern musst du dich erneut anmelden.</h1>`;
      button.innerHTML = `<a class="bottom" href="/login?ref=auth.betahuhn.de/new-password"><button class="btn btn--primary uppercase">Anmelden</button></a>`;
    }else{
      out.innerHTML = `<h1>Es ist ein Fehler aufgetreten.\nBitte versuche es später erneut.</h1>`;
    }
    
}
















