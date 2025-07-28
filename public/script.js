// public/script.js - Versão com a funcionalidade "Em breve" para o botão Editar

document.addEventListener('DOMContentLoaded', () => {

    // --- FUNÇÃO PARA INICIALIZAR A LÓGICA DO DASHBOARD ---
    function initializeDashboardFeatures() {
        const urlInput = document.getElementById('urlInput');
        const downloadBtn = document.getElementById('downloadBtn');
        const editBtn = document.getElementById('editBtn');
        const wpThemeBtn = document.getElementById('wpThemeBtn');
        const loadingDiv = document.getElementById('loading');

        // Verifica se os elementos do dashboard existem nesta página
        // Esta verificação continua a ser útil se esta script for usada noutras páginas
        if (!urlInput || !downloadBtn || !editBtn || !wpThemeBtn || !loadingDiv) {
            console.log("Elementos do Dashboard não encontrados nesta página. Pulando inicialização do Dashboard.");
            return; 
        }

        console.log("Inicializando funcionalidades do Dashboard...");

        function showLoading(isLoading, message = 'A processar...') {
            loadingDiv.textContent = message;
            loadingDiv.classList.toggle('hidden', !isLoading);
            downloadBtn.disabled = isLoading;
            editBtn.disabled = isLoading;
            wpThemeBtn.disabled = isLoading;
        }

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

        // --- Ações dos Botões Principais ---

        // ############### ALTERAÇÃO AQUI ###############
        // O botão "Editar" agora exibe uma mensagem de "Em breve" em vez de redirecionar.
        editBtn.addEventListener('click', (event) => {
            // Previne qualquer comportamento padrão que o botão possa ter.
            event.preventDefault(); 
            
            // Exibe o alerta para o utilizador.
            alert('Em breve: A funcionalidade de edição estará disponível numa futura atualização!');
        });
        // ############################################

        // Botão "Baixar ZIP" (Funcionalidade mantida)
        downloadBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (!url.startsWith('http')) { alert('Por favor, insira um URL válido.'); return; }
            downloadFile('/clonar-e-baixar', url, 'A clonar e a compactar o site...');
        });

        // Botão para gerar o tema WordPress (Funcionalidade mantida)
        wpThemeBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (!url.startsWith('http')) { alert('Por favor, insira um URL válido.'); return; }
            downloadFile('/gerar-tema-wp', url, 'A gerar o tema WordPress...');
        });
    }

    // --- FUNÇÃO PARA INICIALIZAR A LÓGICA DO DROPDOWN DO PERFIL ---
    function initializeProfileDropdown() {
        const profileDropdown = document.querySelector('.dropdown');
        const profileButton = document.querySelector('.profile-button');

        if (profileDropdown && profileButton) {
            profileButton.addEventListener('click', (event) => {
                event.stopPropagation();
                profileDropdown.classList.toggle('show');
            });

            document.addEventListener('click', (event) => {
                if (!profileDropdown.contains(event.target)) {
                    profileDropdown.classList.remove('show');
                }
            });
        } else {
            console.warn("Elementos do dropdown do perfil não encontrados.");
        }
    }

    // --- CHAMA AS FUNÇÕES DE INICIALIZAÇÃO ---
    initializeDashboardFeatures();
    initializeProfileDropdown();
});
