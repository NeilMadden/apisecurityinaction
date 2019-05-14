const apiUrl = 'https://localhost:4567';

function login(username, password) {
    let data = {username, password};

    fetch(apiUrl + '/sessions', {
        method: 'POST',
        body: JSON.stringify(data),
        credentials: "include",
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(res => {
       if (res.ok) window.location.replace('/natter.html');
    })
    .catch(error => console.error('Error logging in: ', error));
}

window.addEventListener('load', function(e) {
    document.getElementById('login')
        .addEventListener('submit', processLoginSubmit);
});

function processLoginSubmit(e) {
    e.preventDefault();

    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    login(username, password);
    return false;
}
