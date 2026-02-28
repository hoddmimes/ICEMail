
async function fetchMailboxes() {
    const tbody = document.getElementById('mailboxBody');

    const result = await callServer('/web/mailboxes');

    if (!result) {
        // Error already handled by callServer/handleError
        tbody.innerHTML = '<tr><td colspan="3" class="error">Failed to load mailboxes</td></tr>';
        return;
    }

    const mailboxes = result.data;
    tbody.innerHTML = '';

    if (!mailboxes || mailboxes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="loading">No mailboxes found</td></tr>';
        return;
    }

    mailboxes.forEach(mailbox => {
        const tr = document.createElement('tr');
        tr.className = 'mailbox-row';

        const unreadCount = mailbox.unreadCount || 0;
        const unreadClass = unreadCount > 0 ? 'unread-count' : '';

        tr.innerHTML = `
            <td>
                <a class="mailbox-link" href="messages.html?folder=${encodeURIComponent(mailbox.fullName)}">
                    ${escapeHtml(mailbox.name)}
                </a>
            </td>
            <td class="count-cell">${mailbox.messageCount || 0}</td>
            <td class="count-cell ${unreadClass}">${unreadCount}</td>
        `;
        tbody.appendChild(tr);
    });
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', fetchMailboxes);
