// public/script.js - Versão com o botão "Editar" desativado temporariamente

document.addEventListener('DOMContentLoaded', () => {
    // Pega nos elementos da página
    const urlInput = document.getElementById('urlInput');
    const downloadBtn = document.getElementById('downloadBtn');
    const editBtn = document.getElementById('editBtn');
    const wpThemeBtn = document.getElementById('wpThemeBtn');
    const loadingDiv = document.getElementById('loading');

    // Se algum elemento principal não for encontrado, o script não continua
    if (!urlInput || !downloadBtn || !editBtn || !wpThemeBtn || !loadingDiv) {
        console.error("Um ou mais elementos essenciais da UI não foram encontrados. Verifica os IDs no ficheiro .ejs.");
        return; 
    }

    // Mostra/esconde a div de loading e desativa/ativa os botões
    function showLoading(isLoading, message = 'A processar...') {
        loadingDiv.textContent = message;
        loadingDiv.classList.toggle('hidden', !isLoading);
        downloadBtn.disabled = isLoading;
        editBtn.disabled = isLoading;
        wpThemeBtn.disabled = isLoading;
    }

    // Função para descarregar ficheiros ZIP a partir de um endpoint do nosso servidor
    async function downloadFile(endpoint, url, loadingMessage) {
        showLoading(true, loadingMessage);
        try {
            const response = await fetch(`${endpoint}?url=${encodeURIComponent(url)}`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Falha na resposta do servidor.');
            }
            const blob = await response.blob();
            const header = response.headers.get('Content-Disposition');
            let fileName = 'download.zip';
            if (header) {
                const parts = header.split('filename="');
                if (parts[1]) fileName = parts[1].replace(/"/g, '');
            }
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = window.URL.createObjectURL(blob);
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(a.href);
        } catch (error) {
            alert(`Erro: ${error.message}`);
        } finally {
            showLoading(false);
        }
    }

    // --- Ações dos Botões ---

    // ALTERAÇÃO AQUI: Botão "Editar" agora mostra um alerta
    editBtn.addEventListener('click', () => {
        alert('Funcionalidade de edição visual - Em breve!');
    });

    // Os outros botões continuam a funcionar normalmente
    downloadBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url.startsWith('http')) { alert('Por favor, insira um URL válido.'); return; }
        downloadFile('/clonar-e-baixar', url, 'A clonar e a compactar o site...');
    });

    wpThemeBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url.startsWith('http')) { alert('Por favor, insira um URL válido.'); return; }
        downloadFile('/gerar-tema-wp', url, 'A gerar o tema WordPress...');
    });
});