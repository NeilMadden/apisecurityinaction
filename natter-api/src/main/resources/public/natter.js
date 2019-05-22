const apiUrl = 'https://localhost:4567';

function createSpace(name, owner) {
    let data = {name: name, owner: owner};
    let token = getCookie('token');

    fetch(apiUrl + '/spaces', {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        }
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else if (response.status === 401) {
            window.location.replace('/login.html');
        } else {
            throw Error(response.statusText);
        }
    })
    .then(json => console.log('Created space: ', json.name, json.uri))
    .catch(error => console.error('Error: ', error));
}

function getCookie(cookieName) {
    var cookieValue = document.cookie.split(';')
        .map(item => item.split('=')
            .map(x => decodeURIComponent(x.trim())))
        .filter(item => item[0] === cookieName)[0]

    if (cookieValue) {
        return cookieValue[1];
    }
}

window.addEventListener('load', function(e) {
    document.getElementById('createSpace')
        .addEventListener('submit', processFormSubmit);
});

function processFormSubmit(e) {
    e.preventDefault();

    let spaceName = document.getElementById('spaceName').value;
    let owner = document.getElementById('owner').value;

    createSpace(spaceName, owner);

    return false;
}
