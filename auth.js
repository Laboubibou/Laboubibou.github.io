// Configuration Firebase
const firebaseConfig = {
    apiKey: "AIzaSyD9OwXwwzkz4D9ICgwj4BTh1_cHJV2UVWA",
   authDomain: "creation-de-compte-1.firebaseapp.com",
   projectId: "creation-de-compte-1",
   storageBucket: "creation-de-compte-1.firebasestorage.app",
   messagingSenderId: "58322653126",
   appId: "1:58322653126:web:1450b24d37459598362cc7",
};

// Initialisation Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();

// Gestion de la connexion
async function handleLogin(email, password) {
    try {
        const userCredential = await auth.signInWithEmailAndPassword(email, password);
        localStorage.setItem('user', JSON.stringify(userCredential.user));
        window.location.href = 'index.html';
    } catch (error) {
        showError(error.message);
    }
}

// Gestion de l'inscription
async function handleRegister(username, email, password) {
    try {
        const userCredential = await auth.createUserWithEmailAndPassword(email, password);
        await userCredential.user.updateProfile({
            displayName: username
        });
        localStorage.setItem('user', JSON.stringify(userCredential.user));
        window.location.href = 'index.html';
    } catch (error) {
        showError(error.message);
    }
}

// Affichage des erreurs
function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

// Vérification de l'état de connexion
auth.onAuthStateChanged(user => {
    if (user) {
        localStorage.setItem('user', JSON.stringify(user));
    } else {
        localStorage.removeItem('user');
    }
});