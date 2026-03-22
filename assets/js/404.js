document.addEventListener('DOMContentLoaded', function(){
    // Number counting animation
    const errorCode = document.querySelector('.error-code');
    if(errorCode) {
        const end = 404;
        const duration = 2000;
        const start = 0;
        let startTime = null;

        function animate(currentTime) {
            if (!startTime) startTime = currentTime;
            const progress = Math.min((currentTime - startTime) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);

            errorCode.textContent = Math.floor(start + (end - start) * ease);

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        }

        requestAnimationFrame(animate);
    }
});