<script>
  const firebaseConfig = {
    apiKey: "AIzaSyD9OwXwwzkz4D9ICgwj4BTh1_cHJV2UVWA",
    authDomain: "creation-de-compte-1.firebaseapp.com",
    projectId: "creation-de-compte-1",
    storageBucket: "creation-de-compte-1.appspot.com",
    messagingSenderId: "58322653126",
    appId: "1:58322653126:web:1450b24d37459598362cc7"
  };

firebase.initializeApp(firebaseConfig);

document.getElementById('loginFormElement').addEventListener('submit', (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    firebase.auth().signInWithEmailAndPassword(email, password)
        .then((userCredential) => {
      window.location.href = 'index.html';
        })
        .catch((error) => {
            document.getElementById('loginError').textContent = error.message;
            document.getElementById('loginError').style.display = 'block';
        });
});

document.getElementById('registerFormElement').addEventListener('submit', (e) => {
    e.preventDefault();
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const username = document.getElementById('registerUsername').value;

    firebase.auth().createUserWithEmailAndPassword(email, password)
        .then((userCredential) => {
            return userCredential.user.updateProfile({
                displayName: username
            });
        })
        .then(() => {
      window.location.href = 'index.html';
        })
        .catch((error) => {
            document.getElementById('registerError').textContent = error.message;
            document.getElementById('registerError').style.display = 'block';
        });
});

firebase.auth().onAuthStateChanged((user) => {
    if (user) {
      localStorage.setItem('user', JSON.stringify(user));
    } else {
      localStorage.removeItem('user');
    }
  });
</script>

