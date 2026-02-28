globalThis.profile = null;





async function F_setProfile() {
   const profile =  document.getElementById("profile");
   const juser = {"profileId" : profile.value };
   response = await postData("/setprofile", juser );
   if (response['success']) {
     globalThis.profile = response['message'];
     prfinp = document.getElementById("profile");
     prfinp.value = profileId(response['message']['profileId']);
   }
}

function F_init() {
    prfinp = document.getElementById("profile");
    prfinp.addEventListener("change", F_setProfile);
    prfinp.addEventListener("keydown", e => {
        if (e.key === "Enter") {
            this.blur(); // triggers change
        }
    });
    F_setProfile();
}

function F_loadContent(section, btn, initFunction) {
  // Update active button
  document.querySelectorAll("nav button")
    .forEach(b => b.classList.remove("active"));
  btn.classList.add("active");


  fetch(`${section}.html`)
    .then(response => {
      if (!response.ok) {
        throw new Error("Content not found");
      }
      return response.text();
    })
    .then(html => {
      document.getElementById("content").innerHTML = html;
      if (initFunction != null) {
        initFunction( globalThis.profile );
      }
    })
    .catch(err => {
      document.getElementById("content").innerHTML =
        "<p>Error loading content.</p>";
      console.error(err);
    });
}

// Load default content on page load
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("nav button")
      .forEach(b => b.classList.remove("active"));
  fetch(`Intro.html`)
      .then(response => {
        if (!response.ok) {
          throw new Error("Content not found");
        }
        return response.text();
      })
      .then(html => {
        document.getElementById("content").innerHTML = html;
      })

    F_init();
});


