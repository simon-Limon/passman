window.onload = async function fetchVaultEntries() {
    const response = await fetch("/getVaultEntries");
    if (!response.ok) {
        console.error("Failed to fetch vault entries");
        return;
    }
    const entries = await response.json();
    const accordion = document.getElementById("accordion");

    accordion.innerHTML = '';
    entries.forEach((entry, index) => {
        const entryHtml = `
            <div class="card" id="card${entry.entryID}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <a class="btn" data-bs-toggle="collapse" href="#collapse${index}">
                        ${entry.serviceName}
                    </a>
                    <button class="btn btn-outline-danger" onclick="deleteEntry('${entry.entryID}')">
                        <i class="bi bi-trash-fill"></i>
                    </button>
                </div>
                <div id="collapse${index}" class="collapse ${index}" data-bs-parent="#accordion">
                    <div class="card-body">
                        <ul class="list-group">
                            <li class="list-group-item">
                                <b>Username</b>
                                <p>${entry.serviceUsername}</p>
                            </li>
                            <li class="list-group-item">
                                <b>Password</b>
                                <p id="passwordPlaceholder${index}">*********</p>
                                <p id="password${index}" style="display: none;">${entry.servicePassword}</p>
                                <button class="btn btn-outline-primary" onclick="togglePassword(${index})">Show</button>
                                <button class="btn btn-outline-secondary" onclick="copyToClipboard('password${index}')">Copy</button>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
        accordion.innerHTML += entryHtml;
    });
};

function deleteEntry(entryID) {
    if (!confirm("Do you want to delete this vault item?")) return;

    fetch(`/deleteVaultEntry/${entryID}`, {
        method: 'DELETE',
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to delete the entry');
        }
        return response.json();
    })
    .then(data => {
        console.log('Entry deleted:', data);
        document.getElementById(`card${entryID}`).remove();
    })
    .catch(error => {
        console.error('Error:', error);
    });
}


function togglePassword(index) {
    const password = document.getElementById(`password${index}`);
    const passwordPlaceholder = document.getElementById(`passwordPlaceholder${index}`);
    const showButton = password.nextElementSibling;

    if (password.style.display === "none") {
        password.style.display = "block";
        passwordPlaceholder.style.display = "none";
        showButton.textContent = "Hide";
    } else {
        password.style.display = "none";
        passwordPlaceholder.style.display = "block";
        showButton.textContent = "Show";
    }
}

function copyToClipboard(elementId) {
    const passwordSpan = document.getElementById(elementId);
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(passwordSpan.textContent)
    }
}