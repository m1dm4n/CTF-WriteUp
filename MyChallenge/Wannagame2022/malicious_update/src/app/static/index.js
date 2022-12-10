function Upload(inp) {
    let formData = new FormData();
    let zip = inp.files[0];

    formData.append("file", zip);

    fetch('/update', { method: "POST", body: formData })
        .then(r => r.text())
        .then(data => {
            result.innerHTML = data;
        });
}