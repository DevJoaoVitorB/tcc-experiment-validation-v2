# Instruções Gerais do Projeto

## 1. Documentação

Antes de iniciar o desenvolvimento, leia todos os documentos disponíveis na pasta `docs/` e considere as instruções e especificações neles contidas durante a implementação da aplicação.

## 2. Tecnologias

Utilize as seguintes tecnologias no desenvolvimento:

- **Express** para desenvolvimento da API;
- **TypeScript** como linguagem de desenvolvimento;
- **Prisma** para gerenciamento e acesso ao banco de dados;
- **SQLite** como banco de dados.

## 3. Arquitetura e implementação

Defina livremente a arquitetura, a organização dos arquivos, os componentes internos e as estratégias de implementação necessárias para atender às especificações, respeitando as tecnologias especificadas.

## 4. Modelagem de dados

Defina a modelagem de dados com base nos requisitos funcionais especificados, contemplando os dados necessários para o funcionamento da aplicação, com liberdade para determinar sua estrutura e organização.

## 5. Configuração e execução

Crie os arquivos de configuração e os componentes necessários para instalar, executar e testar a aplicação, incluindo os arquivos necessários para construir uma imagem Docker e executar a aplicação em um container.

Documente no arquivo `README.md` os procedimentos necessários para instalação, configuração e execução da aplicação, incluindo os comandos utilizados e as instruções para execução por meio de container Docker.

As instruções devem corresponder aos arquivos e procedimentos efetivamente disponibilizados no projeto.

## 6. Verificação

Execute as verificações e os testes pertinentes ao funcionamento da aplicação, conforme as condições disponíveis, e corrija os erros funcionais identificados em relação aos requisitos especificados.

Documente no arquivo `README.md` as verificações e os testes efetivamente executados, seus respectivos comandos ou procedimentos e os resultados obtidos.

Registre também os testes e verificações que não puderam ser realizados, indicando os motivos e as limitações encontradas.

Os registros devem corresponder às atividades efetivamente realizadas e aos resultados observados, sem apresentar como executados testes ou verificações que não foram realizados.

## 7. Documentação da API

A especificação OpenAPI deve representar fielmente a API implementada, contemplando todas as operações disponibilizadas, seus respectivos caminhos, métodos HTTP, parâmetros, dados de entrada, estruturas de resposta e códigos de status correspondentes.

A especificação deve estar disponível por meio de uma rota HTTP no endereço `/openapi.json`, permitindo sua consulta automatizada pelos procedimentos de validação e análise da aplicação.

Cada operação deve possuir um identificador semântico (`operationId`) único e estável, que permita identificar sua finalidade independentemente do caminho HTTP utilizado.

Nas operações relacionadas aos requisitos funcionais, os identificadores devem permitir reconhecer semanticamente suas respectivas finalidades, sem exigir caminhos HTTP ou métodos específicos.

A documentação dos mecanismos de autenticação e das operações protegidas deve corresponder ao comportamento efetivamente implementado, incluindo as informações necessárias para identificar os mecanismos de autenticação e interpretar as estruturas de entrada e saída.

A documentação deve permanecer consistente com o comportamento efetivamente implementado, sem omitir operações ou descrever funcionalidades inexistentes.

A geração da especificação deve respeitar a liberdade de escolha da arquitetura, organização interna, nomenclatura e mecanismos de implementação, não sendo exigida a utilização de biblioteca ou estrutura específica.

Registre no arquivo `README.md` o endereço de disponibilização da especificação OpenAPI e as informações necessárias para sua consulta.

## 8. Escopo

Implemente todos os requisitos funcionais especificados, tomando as decisões técnicas necessárias para atender ao comportamento esperado da aplicação.

Não considere funcionalidades, mecanismos ou requisitos adicionais como obrigatórios, exceto quando forem necessários para implementar os requisitos especificados ou garantir o funcionamento da aplicação.
