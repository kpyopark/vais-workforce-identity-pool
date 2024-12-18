function handleCredentialResponse(response) {
  // 토큰을 백엔드로 전송
  fetch('/auth/google', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
      },
      body: JSON.stringify({
          token: response.credential
      })
  })
  .then(response => response.json())
  .then(data => {
      console.log('Success:', data);
  })
  .catch((error) => {
      console.error('Error:', error);
  });
}