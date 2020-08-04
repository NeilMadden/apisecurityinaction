function getCap(url, callback) {
    let capUrl = new URL(url);
    let token = capUrl.hash.substring(1);
    capUrl.hash = '';
    capUrl.search = '?access_token=' + token;

    return fetch(capUrl.href)
    .then(response => response.json())
    .then(callback)
    .catch(err => console.error('Error: ', err));
}