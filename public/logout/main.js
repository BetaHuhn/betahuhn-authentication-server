const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    error = document.getElementById('error')

function button() {
    delete_cookie("token", "/", ".betahuhn.de")
    window.location.replace("/");
}
function delete_cookie( name, path, domain ) {
    if( getCookie( name ) ) {
        document.cookie = name + "=" +
        ((path) ? ";path="+path:"")+
        ((domain)?";domain="+domain:"") +
        ";expires=Thu, 01 Jan 1970 00:00:01 GMT";
    }
}
function getCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}