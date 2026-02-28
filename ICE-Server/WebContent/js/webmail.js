/* ICE Mail SPA Controller */

(function () {
    'use strict';

    // State
    let currentFolder = null;
    let currentOffset = 0;
    let currentMessages = [];
    let mailboxes = [];
    let currentView = 'messages'; // messages | message | contacts | compose

    // -- Encryption helpers (mirrors TH-add-on/background.js) ------------------

    function arrayBufferToBase64(buffer) {
        let bytes = new Uint8Array(buffer);
        let binary = "";
        for (let b of bytes) {
            binary += String.fromCharCode(b);
        }
        return btoa(binary);
    }

    function generateHexUID(byteLength) {
        let bytes = crypto.getRandomValues(new Uint8Array(byteLength));
        return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    }

    async function encryptBody(body, password) {
        let encoder = new TextEncoder();
        let salt = crypto.getRandomValues(new Uint8Array(16));
        let iv = crypto.getRandomValues(new Uint8Array(12));

        let keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );
        let key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt,
                iterations: 100000,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        let ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            encoder.encode(body)
        );

        let payload = JSON.stringify({
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
        });

        return btoa(payload);
    }

    function wrapEncryptedBody(base64Payload) {
        return (
            "-----BEGIN ICE ENCRYPTED MESSAGE-----\n" +
            base64Payload +
            "\n-----END ICE ENCRYPTED MESSAGE-----"
        );
    }

    // DOM refs
    const content = document.getElementById('content');
    const mailboxBtn = document.getElementById('mailboxBtn');
    const mailboxLabel = document.getElementById('mailboxLabel');
    const mailboxDropdown = document.getElementById('mailboxDropdown');
    const contactsBtn = document.getElementById('contactsBtn');
    const composeBtn = document.getElementById('composeBtn');

    // Utility
    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // ===== Initialization =====

    async function init() {
        mailboxBtn.addEventListener('click', toggleDropdown);
        contactsBtn.addEventListener('click', showContacts);
        composeBtn.addEventListener('click', showCompose);

        document.addEventListener('click', function (e) {
            if (!mailboxBtn.contains(e.target) && !mailboxDropdown.contains(e.target)) {
                mailboxDropdown.classList.remove('open');
            }
        });

        await fetchMailboxes();
    }

    function toggleDropdown(e) {
        e.stopPropagation();
        mailboxDropdown.classList.toggle('open');
    }

    // ===== Mailbox Dropdown =====

    async function fetchMailboxes() {
        const result = await callServer('/web/mailboxes');
        if (!result) {
            content.innerHTML = '<div class="loading">Failed to load mailboxes</div>';
            return;
        }

        mailboxes = result.data || [];

        renderDropdown();

        if (mailboxes.length > 0) {
            selectFolder(mailboxes[0].fullName);
        } else {
            content.innerHTML = '<div class="empty">No mailboxes with messages found</div>';
        }
    }

    function renderDropdown() {
        mailboxDropdown.innerHTML = '';
        mailboxes.forEach(function (mb) {
            const item = document.createElement('div');
            item.className = 'dropdown-item' + (mb.fullName === currentFolder ? ' active' : '');

            let countHtml = '<span class="dropdown-count">' + (mb.messageCount || 0) + '</span>';
            if (mb.unreadCount > 0) {
                countHtml = '<span class="dropdown-count dropdown-unread">' + mb.unreadCount + ' / ' + mb.messageCount + '</span>';
            }

            item.innerHTML = '<span>' + escapeHtml(mb.name) + '</span>' + countHtml;
            item.addEventListener('click', function () {
                mailboxDropdown.classList.remove('open');
                selectFolder(mb.fullName);
            });
            mailboxDropdown.appendChild(item);
        });
    }

    function selectFolder(folderName) {
        currentFolder = folderName;
        currentOffset = 0;
        currentMessages = [];
        mailboxLabel.textContent = folderName;
        renderDropdown();
        fetchMessages();
    }

    // ===== Messages View =====

    async function fetchMessages() {
        currentView = 'messages';
        if (currentOffset === 0) {
            content.innerHTML = '<div class="loading">Loading messages...</div>';
        }

        const url = '/web/messages?folder=' + encodeURIComponent(currentFolder) + '&offset=' + currentOffset;
        const result = await callServer(url);
        if (!result) return;

        const data = result.data;
        const msgs = data.messages || [];
        currentMessages = currentMessages.concat(msgs);

        renderMessages(data.total, data.hasMore);
    }

    function renderMessages(total, hasMore) {
        let html = '<div class="messages-container">';
        html += '<div class="messages-header">';
        html += '<h2>' + escapeHtml(currentFolder) + '</h2>';
        html += '<span class="message-count">' + total + ' messages</span>';
        html += '</div>';

        if (currentMessages.length === 0) {
            html += '<div class="empty">No messages in this folder</div>';
        } else {
            html += '<ul class="message-list">';
            currentMessages.forEach(function (msg) {
                const unreadClass = msg.unread ? ' unread' : '';
                html += '<li class="message-item' + unreadClass + '">';
                html += '<div class="message-item-wrapper">';
                html += '<div class="message-link" data-folder="' + escapeHtml(currentFolder) + '" data-msg="' + msg.messageNumber + '">';
                html += '<div class="message-row">';
                html += '<span class="message-date">' + escapeHtml(msg.date) + '</span>';
                html += '<span class="message-from">' + escapeHtml(msg.from) + '</span>';
                html += '<span class="message-to">' + escapeHtml(msg.to) + '</span>';
                html += '<span class="message-subject">' + escapeHtml(msg.subject || '(No subject)') + '</span>';
                html += '</div></div>';
                html += '<button class="btn-sm btn-danger message-delete-btn" data-folder="' + escapeHtml(currentFolder) + '" data-msg="' + msg.messageNumber + '">Delete</button>';
                html += '</div></li>';
            });
            html += '</ul>';

            if (hasMore) {
                html += '<div class="more-container"><button class="more-btn" id="moreBtn">More</button></div>';
            }
        }

        html += '</div>';
        content.innerHTML = html;

        // Wire click handlers
        content.querySelectorAll('.message-link').forEach(function (el) {
            el.addEventListener('click', function () {
                showMessage(el.dataset.folder, el.dataset.msg);
            });
        });

        content.querySelectorAll('.message-delete-btn').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                deleteMessage(btn.dataset.folder, btn.dataset.msg);
            });
        });

        var moreBtn = document.getElementById('moreBtn');
        if (moreBtn) {
            moreBtn.addEventListener('click', function () {
                currentOffset += currentMessages.length > currentOffset ? (currentMessages.length - currentOffset) : 25;
                // Recalculate: offset should increase by the batch that was fetched
                currentOffset = currentMessages.length;
                fetchMessages();
            });
        }
    }

    // ===== Delete Message =====

    async function deleteMessage(folder, msgNum) {
        if (!confirm('Delete this message?')) return;
        const result = await callServer('/web/message/delete', {
            method: 'POST',
            body: JSON.stringify({ folder: folder, msg: parseInt(msgNum) })
        });
        if (result) {
            currentOffset = 0;
            currentMessages = [];
            fetchMessages();
        }
    }

    // ===== PGP Decryption =====

    async function decryptPgpBody(body) {
        try {
            var password = sessionStorage.getItem('password');
            if (!password) {
                return '[PGP encrypted message - re-login to decrypt]';
            }

            var profileResult = await callServer('/web/profile');
            if (!profileResult || !profileResult.data || !profileResult.data.privateKey) {
                return '[PGP encrypted message - could not load private key]';
            }

            var encPrivateKeyB64 = profileResult.data.privateKey;
            var encPrivateKeyBinary = base64ToUint8Array(encPrivateKeyB64);
            var encMessage = await openpgp.readMessage({ binaryMessage: encPrivateKeyBinary });
            var decResult = await openpgp.decrypt({
                message: encMessage,
                passwords: [password],
                format: 'binary'
            });

            var privateKeyArmored = new TextDecoder().decode(decResult.data);
            var privateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
                passphrase: password
            });

            var pgpMatch = body.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/);
            if (!pgpMatch) {
                return body;
            }

            var pgpMessage = await openpgp.readMessage({ armoredMessage: pgpMatch[0] });
            var pgpResult = await openpgp.decrypt({
                message: pgpMessage,
                decryptionKeys: privateKey
            });

            return body.replace(pgpMatch[0], pgpResult.data);
        } catch (e) {
            console.error('PGP decryption failed:', e);
            return '[PGP encrypted message - decryption failed: ' + e.message + ']';
        }
    }

    // ===== Single Message View =====

    async function showMessage(folder, msgNum) {
        currentView = 'message';
        content.innerHTML = '<div class="loading">Loading message...</div>';

        const url = '/web/message?folder=' + encodeURIComponent(folder) + '&msg=' + msgNum;
        const result = await callServer(url);
        if (!result) return;

        const msg = result.data;

        // Decrypt PGP-encrypted body if present
        var bodyText = msg.body || '';
        if (bodyText.indexOf('-----BEGIN PGP MESSAGE-----') >= 0) {
            bodyText = await decryptPgpBody(bodyText);
        }

        let html = '<div class="single-message">';
        html += '<div class="single-message-header">';
        html += '<button class="back-btn" id="backToMessages">&larr;</button>';
        html += '<h2>' + escapeHtml(msg.subject || '(No subject)') + '</h2>';
        html += '<button class="btn-sm btn-danger" id="deleteMessageBtn">Delete</button>';
        html += '</div>';
        html += '<div class="message-meta">';
        html += '<div class="meta-row"><span class="meta-label">Date:</span><span class="meta-value">' + escapeHtml(msg.date) + '</span></div>';
        html += '<div class="meta-row"><span class="meta-label">From:</span><span class="meta-value">' + escapeHtml(msg.from) + '</span></div>';
        html += '<div class="meta-row"><span class="meta-label">To:</span><span class="meta-value">' + escapeHtml(msg.to) + '</span></div>';
        html += '</div>';
        html += '<div class="message-body">' + escapeHtml(bodyText) + '</div>';

        if (msg.attachments && msg.attachments.length > 0) {
            html += '<div class="attachment-list">';
            html += '<div class="attachment-list-header">Attachments (' + msg.attachments.length + ')</div>';
            msg.attachments.forEach(function (att) {
                var attUrl = '/web/attachment?folder=' + encodeURIComponent(folder) + '&msg=' + msgNum + '&part=' + att.partIndex;
                var sizeStr = att.size != null ? formatFileSize(att.size) : '';
                html += '<div class="attachment-item">';
                html += '<a href="' + escapeHtml(attUrl) + '" target="_blank">' + escapeHtml(att.filename) + '</a>';
                if (sizeStr) {
                    html += '<span class="attachment-size">' + sizeStr + '</span>';
                }
                html += '<span class="attachment-type">' + escapeHtml(att.contentType) + '</span>';
                html += '</div>';
            });
            html += '</div>';
        }

        html += '</div>';

        content.innerHTML = html;

        document.getElementById('backToMessages').addEventListener('click', function () {
            currentOffset = 0;
            currentMessages = [];
            fetchMessages();
        });

        document.getElementById('deleteMessageBtn').addEventListener('click', function () {
            deleteMessage(folder, msgNum);
        });
    }

    // ===== Contacts View =====

    let contacts = [];
    let editingContactId = null;

    async function showContacts() {
        currentView = 'contacts';
        mailboxDropdown.classList.remove('open');
        content.innerHTML = '<div class="loading">Loading contacts...</div>';

        const result = await callServer('/web/contacts');
        if (!result) return;

        contacts = result.data || [];
        renderContacts();
    }

    function renderContacts() {
        let html = '<div class="contacts-container">';
        html += '<div class="contacts-header">';
        html += '<h2>Contacts</h2>';
        html += '<button class="menu-btn menu-btn-primary" id="addContactBtn">Add Contact</button>';
        html += '</div>';

        // Inline form (hidden by default)
        html += '<div id="contactFormArea"></div>';

        if (contacts.length === 0) {
            html += '<div class="empty">No contacts yet</div>';
        } else {
            html += '<table class="contacts-table">';
            html += '<thead><tr><th>Name</th><th>Email</th><th>Actions</th></tr></thead>';
            html += '<tbody>';
            contacts.forEach(function (c) {
                html += '<tr>';
                html += '<td>' + escapeHtml(c.name) + '</td>';
                html += '<td>' + escapeHtml(c.email) + '</td>';
                html += '<td class="contact-actions">';
                html += '<button class="btn-sm" data-action="edit" data-id="' + c.id + '">Edit</button>';
                html += '<button class="btn-sm btn-danger" data-action="delete" data-id="' + c.id + '">Delete</button>';
                html += '</td></tr>';
            });
            html += '</tbody></table>';
        }

        html += '</div>';
        content.innerHTML = html;

        document.getElementById('addContactBtn').addEventListener('click', function () {
            editingContactId = null;
            showContactForm('', '');
        });

        content.querySelectorAll('[data-action="edit"]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const id = parseInt(btn.dataset.id);
                const c = contacts.find(function (x) { return x.id === id; });
                if (c) {
                    editingContactId = id;
                    showContactForm(c.name, c.email);
                }
            });
        });

        content.querySelectorAll('[data-action="delete"]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const id = parseInt(btn.dataset.id);
                const c = contacts.find(function (x) { return x.id === id; });
                if (c && confirm('Delete contact "' + c.name + '"?')) {
                    deleteContact(id);
                }
            });
        });
    }

    function showContactForm(name, email) {
        const area = document.getElementById('contactFormArea');
        const isEdit = editingContactId !== null;
        area.innerHTML =
            '<div class="contact-form">' +
            '<div class="form-group"><label>Name</label><input type="text" id="contactName" value="' + escapeHtml(name) + '"></div>' +
            '<div class="form-group"><label>Email</label><input type="email" id="contactEmail" value="' + escapeHtml(email) + '"></div>' +
            '<div class="contact-form-buttons">' +
            '<button class="menu-btn menu-btn-primary" id="saveContactBtn">' + (isEdit ? 'Update' : 'Save') + '</button>' +
            '<button class="menu-btn" id="cancelContactBtn">Cancel</button>' +
            '</div></div>';

        document.getElementById('saveContactBtn').addEventListener('click', saveContact);
        document.getElementById('cancelContactBtn').addEventListener('click', function () {
            editingContactId = null;
            area.innerHTML = '';
        });

        document.getElementById('contactName').focus();
    }

    async function saveContact() {
        const name = document.getElementById('contactName').value.trim();
        const email = document.getElementById('contactEmail').value.trim();

        if (!name || !email) {
            displayError('Validation', 'Name and email are required');
            return;
        }

        let result;
        if (editingContactId !== null) {
            result = await callServer('/web/contacts/update', {
                method: 'POST',
                body: JSON.stringify({ id: editingContactId, name: name, email: email })
            });
        } else {
            result = await callServer('/web/contacts/create', {
                method: 'POST',
                body: JSON.stringify({ name: name, email: email })
            });
        }

        if (result) {
            editingContactId = null;
            showContacts();
        }
    }

    async function deleteContact(id) {
        const result = await callServer('/web/contacts/delete', {
            method: 'POST',
            body: JSON.stringify({ id: id })
        });

        if (result) {
            showContacts();
        }
    }

    // ===== Compose View =====

    let composeContacts = [];

    function addressFieldHtml(label, id, placeholder) {
        return '<div class="form-group">' +
            '<label>' + label + '</label>' +
            '<div class="address-field">' +
            '<input type="text" id="' + id + '" placeholder="' + (placeholder || '') + '" autocomplete="off">' +
            '<div class="address-suggestions" id="' + id + 'Suggestions"></div>' +
            '</div></div>';
    }

    async function showCompose() {
        currentView = 'compose';
        mailboxDropdown.classList.remove('open');

        // Load contacts for autocomplete
        const contactResult = await callServer('/web/contacts');
        composeContacts = (contactResult && contactResult.data) ? contactResult.data : [];

        let html = '<div class="compose-container">';
        html += '<div class="compose-header"><h2>New Message</h2></div>';
        html += '<div class="compose-form">';
        html += addressFieldHtml('To', 'composeTo', 'recipient@example.com');
        html += addressFieldHtml('CC', 'composeCc', '');
        html += addressFieldHtml('BCC', 'composeBcc', '');
        html += '<div class="form-group"><label>Subject</label><input type="text" id="composeSubject" placeholder=""></div>';
        html += '<div class="form-group encrypt-group">';
        html += '<label><input type="checkbox" id="composeEncrypt"> Encrypt with password</label>';
        html += '<input type="password" id="composeEncryptPassword" placeholder="Min 8 characters" disabled>';
        html += '</div>';
        html += '<div class="form-group"><label>Message</label><textarea id="composeBody"></textarea></div>';
        html += '<div class="form-group"><label>Attachments</label><input type="file" id="composeFiles" multiple><ul class="compose-file-list" id="composeFileList"></ul></div>';
        html += '<div class="compose-form-buttons">';
        html += '<button class="menu-btn menu-btn-primary" id="composeSendBtn">Send</button>';
        html += '<button class="menu-btn" id="composeCancelBtn">Cancel</button>';
        html += '</div>';
        html += '</div></div>';

        content.innerHTML = html;

        // Wire autocomplete on address fields
        ['composeTo', 'composeCc', 'composeBcc'].forEach(function (id) {
            setupAddressAutocomplete(document.getElementById(id), document.getElementById(id + 'Suggestions'));
        });

        document.getElementById('composeFiles').addEventListener('change', function () {
            var list = document.getElementById('composeFileList');
            list.innerHTML = '';
            for (var i = 0; i < this.files.length; i++) {
                var li = document.createElement('li');
                li.textContent = this.files[i].name;
                list.appendChild(li);
            }
        });

        document.getElementById('composeEncrypt').addEventListener('change', function () {
            document.getElementById('composeEncryptPassword').disabled = !this.checked;
            if (!this.checked) {
                document.getElementById('composeEncryptPassword').value = '';
            }
        });

        document.getElementById('composeSendBtn').addEventListener('click', composeSend);
        document.getElementById('composeCancelBtn').addEventListener('click', function () {
            currentOffset = 0;
            currentMessages = [];
            fetchMessages();
        });

        document.getElementById('composeTo').focus();
    }

    // --- Address autocomplete helpers ---

    function getCurrentToken(input) {
        var val = input.value;
        var cursor = input.selectionStart;
        var before = val.substring(0, cursor);
        var lastComma = before.lastIndexOf(',');
        return before.substring(lastComma + 1).trim();
    }

    function replaceCurrentToken(input, replacement) {
        var val = input.value;
        var cursor = input.selectionStart;
        var before = val.substring(0, cursor);
        var after = val.substring(cursor);
        var lastComma = before.lastIndexOf(',');
        var prefix = lastComma >= 0 ? before.substring(0, lastComma + 1) + ' ' : '';
        // Find next comma in "after" to preserve subsequent addresses
        var nextComma = after.indexOf(',');
        var suffix = nextComma >= 0 ? after.substring(nextComma) : '';
        input.value = prefix + replacement + ', ' + suffix.replace(/^,\s*/, '');
        // Place cursor after the inserted address
        var newCursor = (prefix + replacement + ', ').length;
        input.setSelectionRange(newCursor, newCursor);
    }

    function filterContacts(token) {
        if (!token) return [];
        var lower = token.toLowerCase();
        return composeContacts.filter(function (c) {
            return c.name.toLowerCase().indexOf(lower) >= 0 ||
                   c.email.toLowerCase().indexOf(lower) >= 0;
        });
    }

    function setupAddressAutocomplete(input, suggestionsEl) {
        var activeIndex = -1;

        function showSuggestions() {
            var token = getCurrentToken(input);
            var matches = filterContacts(token);

            if (matches.length === 0) {
                suggestionsEl.classList.remove('open');
                suggestionsEl.innerHTML = '';
                activeIndex = -1;
                return;
            }

            activeIndex = -1;
            suggestionsEl.innerHTML = '';
            matches.forEach(function (c, i) {
                var div = document.createElement('div');
                div.className = 'address-suggestion';
                div.innerHTML = '<span class="suggestion-name">' + escapeHtml(c.name) + '</span>' +
                    '<span class="suggestion-email">' + escapeHtml(c.email) + '</span>';
                div.addEventListener('mousedown', function (e) {
                    e.preventDefault(); // Prevent blur before click completes
                    selectSuggestion(c);
                });
                suggestionsEl.appendChild(div);
            });
            suggestionsEl.classList.add('open');
        }

        function selectSuggestion(contact) {
            replaceCurrentToken(input, contact.email);
            suggestionsEl.classList.remove('open');
            suggestionsEl.innerHTML = '';
            activeIndex = -1;
            input.focus();
        }

        function updateActive() {
            var items = suggestionsEl.querySelectorAll('.address-suggestion');
            items.forEach(function (el, i) {
                el.classList.toggle('active', i === activeIndex);
            });
            if (activeIndex >= 0 && items[activeIndex]) {
                items[activeIndex].scrollIntoView({ block: 'nearest' });
            }
        }

        input.addEventListener('input', showSuggestions);
        input.addEventListener('focus', showSuggestions);

        input.addEventListener('blur', function () {
            // Small delay to allow mousedown on suggestion to fire
            setTimeout(function () {
                suggestionsEl.classList.remove('open');
            }, 150);
        });

        input.addEventListener('keydown', function (e) {
            var items = suggestionsEl.querySelectorAll('.address-suggestion');
            if (!suggestionsEl.classList.contains('open') || items.length === 0) return;

            if (e.key === 'ArrowDown') {
                e.preventDefault();
                activeIndex = (activeIndex + 1) % items.length;
                updateActive();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                activeIndex = activeIndex <= 0 ? items.length - 1 : activeIndex - 1;
                updateActive();
            } else if (e.key === 'Enter' || e.key === 'Tab') {
                if (activeIndex >= 0) {
                    e.preventDefault();
                    var matchedContacts = filterContacts(getCurrentToken(input));
                    if (matchedContacts[activeIndex]) {
                        selectSuggestion(matchedContacts[activeIndex]);
                    }
                }
            } else if (e.key === 'Escape') {
                suggestionsEl.classList.remove('open');
                activeIndex = -1;
            }
        });
    }

    async function composeSend() {
        var to = document.getElementById('composeTo').value.trim();
        var cc = document.getElementById('composeCc').value.trim();
        var bcc = document.getElementById('composeBcc').value.trim();
        var subject = document.getElementById('composeSubject').value;
        var body = document.getElementById('composeBody').value;
        var files = document.getElementById('composeFiles').files;
        var encrypt = document.getElementById('composeEncrypt').checked;
        var encryptPassword = document.getElementById('composeEncryptPassword').value;

        if (!to) {
            displayError('Validation', 'Recipient (To) is required');
            return;
        }

        if (encrypt && encryptPassword.length < 8) {
            displayError('Validation', 'Encryption password must be at least 8 characters');
            return;
        }

        // Encrypt body client-side if requested
        if (encrypt) {
            try {
                var encrypted = await encryptBody(body, encryptPassword);
                body = wrapEncryptedBody(encrypted);
            } catch (e) {
                displayError('Encryption', 'Failed to encrypt message: ' + e.message);
                return;
            }
        }

        var formData = new FormData();
        formData.append('to', to);
        formData.append('cc', cc);
        formData.append('bcc', bcc);
        formData.append('subject', subject);
        formData.append('body', body);

        if (encrypt) {
            formData.append('iceUid', generateHexUID(16));
        }

        for (var i = 0; i < files.length; i++) {
            formData.append('attachments', files[i]);
        }

        var sendBtn = document.getElementById('composeSendBtn');
        sendBtn.disabled = true;
        sendBtn.textContent = 'Sending...';

        try {
            var response = await fetch('/web/compose/send', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                if (response.status === 401) {
                    window.location.href = '/login.html';
                    return;
                }
                await handleError(response);
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send';
                return;
            }

            var result = await response.json();
            if (!result.success) {
                await handleError(result);
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send';
                return;
            }

            displayError('OK', 'Message sent');
            currentOffset = 0;
            currentMessages = [];
            fetchMessages();

        } catch (err) {
            handleError(err);
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send';
        }
    }

    // ===== Boot =====

    document.addEventListener('DOMContentLoaded', init);

})();
