// public/script.js - Versão com inicialização condicional de funcionalidades

document.addEventListener('DOMContentLoaded', () => {

    // --- FUNÇÃO PARA INICIALIZAR A LÓGICA DO DASHBOARD ---
    function initializeDashboardFeatures() {
        const urlInput = document.getElementById('urlInput');
        const downloadBtn = document.getElementById('downloadBtn');
        const editBtn = document.getElementById('editBtn');
        const wpThemeBtn = document.getElementById('wpThemeBtn');
        const loadingDiv = document.getElementById('loading');

        // Verifica se os elementos do dashboard existem nesta página
        if (!urlInput || !downloadBtn || !editBtn || !wpThemeBtn || !loadingDiv) {
            console.log("Elementos do Dashboard não encontrados nesta página. Pulando inicialização do Dashboard.");
            return; // Sai da função se não for a página do Dashboard
        }

        console.log("Inicializando funcionalidades do Dashboard...");

        // Mostra/esconde a div de loading e desativa/ativa os botões (LÓGICA DO DASHBOARD)
        function showLoading(isLoading, message = 'A processar...') {
            loadingDiv.textContent = message;
            loadingDiv.classList.toggle('hidden', !isLoading);
            downloadBtn.disabled = isLoading;
            editBtn.disabled = isLoading;
            wpThemeBtn.disabled = isLoading;
        }

        // Função para descarregar ficheiros ZIP (LÓGICA DO DASHBOARD)
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

        // --- Ações dos Botões Principais (LÓGICA DO DASHBOARD) ---

        // ATUALIZADO: Botão "Editar" agora redireciona para a página do editor
        editBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (!url.startsWith('http')) {
                alert('Por favor, insira um URL válido para editar.');
                return;
            }
            // Redireciona para a rota /editar no servidor, passando a URL do site
            window.location.href = `/editar?url=${encodeURIComponent(url)}`;
        });

        // Botão "Baixar ZIP"
        downloadBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (!url.startsWith('http')) { alert('Por favor, insira um URL válido.'); return; }
            downloadFile('/clonar-e-baixar', url, 'A clonar e a compactar o site...');
        });

        // Botão para gerar o tema WordPress
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

        console.log('--- Inicializando Dropdown ---');
        console.log('Elemento .dropdown:', profileDropdown);
        console.log('Elemento .profile-button:', profileButton);
        console.log('---------------------------');

        // Verifica se os elementos do dropdown existem nesta página (devem existir em todas as páginas com cabeçalho)
        if (profileDropdown && profileButton) {
            profileButton.addEventListener('click', (event) => {
                event.stopPropagation();
                profileDropdown.classList.toggle('show');
                console.log('Botão de perfil clicado. Classe "show" alternada.');
            });

            document.addEventListener('click', (event) => {
                if (!profileDropdown.contains(event.target)) {
                    profileDropdown.classList.remove('show');
                    console.log('Clicou fora do dropdown. Classe "show" removida.');
                }
            });
        } else {
            console.warn("Elementos do dropdown do perfil não encontrados (normal se esta página não tiver cabeçalho).");
        }
    }

    // --- CHAMA AS FUNÇÕES DE INICIALIZAÇÃO NO DOMContentLoaded ---
    initializeDashboardFeatures(); // Tenta inicializar as funcionalidades do Dashboard
    initializeProfileDropdown();   // Tenta inicializar a lógica do Dropdown do Perfil
});