import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import re
from pathlib import Path
from typing import List
from dataclasses import dataclass
from lxml import etree
import xmlsec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# --- CONFIGURAÇÕES TÉCNICAS SEFAZ ---
NS_DIE = "http://www.sefaz.am.gov.br/die"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NSMAP = {None: NS_DIE, "xsi": NS_XSI}
SCHEMA_LOC = "http://www.sefaz.am.gov.br/die enviGabaritoDIe_v1.00.xsd"


@dataclass
class ItemMatriz:
    destinacao: str
    utilizacao: str
    tributacao: str
    ncm: str
    cod_suframa: str
    numero_documento: str
    numero_decreto: str
    inicio: str
    fim: str
    tipo_documento_concessivo: str = "1"

# --- FUNÇÕES DE LIMPEZA E ASSINATURA ---


def limpar_string_assinatura(root: etree._Element):
    """Remove quebras de linha e espaços de dentro dos blocos da assinatura."""
    tags = [
        "{http://www.w3.org/2000/09/xmldsig#}SignatureValue",
        "{http://www.w3.org/2000/09/xmldsig#}DigestValue",
        "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    ]
    for tag in tags:
        for el in root.iter(tag):
            if el.text:
                el.text = re.sub(r'[\n\r\t\s]', '', el.text)


def limpar_formatacao_xml(root: etree._Element):
    """Remove espaços entre tags para garantir linha única."""
    for el in root.iter():
        if el.text:
            el.text = el.text.strip()
        el.tail = None


def assinar_xml(root: etree._Element, caminho_pfx: str, senha_pfx: str) -> etree._Element:
    with open(caminho_pfx, "rb") as f:
        pfx_data = f.read()

    p_key, cert, _ = load_key_and_certificates(pfx_data, senha_pfx.encode())
    key_pem = p_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cert_pem = cert.public_bytes(Encoding.PEM)

    inf_node = root.find(f".//{{{NS_DIE}}}InfMatrizDIe")
    inf_id = inf_node.get("Id")

    xmlsec.tree.add_ids(root, ["Id"])

    # AJUSTE SEFAZ: Usando C14N (Padrão) em vez de EXCL_C14N para evitar erro de algoritmo fixo
    signature_node = xmlsec.template.create(
        root, xmlsec.Transform.C14N, xmlsec.Transform.RSA_SHA1)
    root.find(f".//{{{NS_DIE}}}MatrizDIe").append(signature_node)

    ref = xmlsec.template.add_reference(
        signature_node, xmlsec.Transform.SHA1, uri=f"#{inf_id}")
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    # AJUSTE SEFAZ: Transformação deve ser o C14N padrão (20010315)
    xmlsec.template.add_transform(ref, xmlsec.Transform.C14N)

    xmlsec.template.add_x509_data(
        xmlsec.template.ensure_key_info(signature_node))

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(key_pem, xmlsec.KeyFormat.PEM)
    ctx.key.load_cert_from_memory(cert_pem, xmlsec.KeyFormat.PEM)
    ctx.sign(signature_node)

    limpar_string_assinatura(root)
    limpar_formatacao_xml(root)
    return root

# --- INTERFACE GRAFICA (MODELO ORIGINAL) ---


class MatrizTributacaoApp:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Matriz de Tributação - XML Assinado")
        self.master.geometry("1280x820")

        self.itens: List[ItemMatriz] = []
        self._criar_variaveis()
        self._criar_layout()

    def _criar_variaveis(self):
        desktop = os.path.join(os.path.expanduser(
            "~"), "Desktop", "matriz_assinada.xml")
        self.var_versao = tk.StringVar(value="1.00")
        self.var_tipo_importador = tk.StringVar(value="1")
        self.var_cd_importador = tk.StringVar(value="062013726")
        self.var_certificado = tk.StringVar()
        self.var_senha = tk.StringVar(value="LMC_AMZ#20260312_A1!")
        self.var_saida = tk.StringVar(value=desktop)

        self.var_destinacao = tk.StringVar(value="05")
        self.var_utilizacao = tk.StringVar(value="03")
        self.var_tributacao = tk.StringVar(value="T510")
        self.var_ncm = tk.StringVar()
        self.var_cod_suframa = tk.StringVar(value="2223")
        self.var_numero_documento = tk.StringVar()
        self.var_numero_decreto = tk.StringVar()
        self.var_inicio = tk.StringVar()
        self.var_fim = tk.StringVar()
        self.var_tipo_documento = tk.StringVar(value="1")

    def _criar_layout(self):
        frame_topo = ttk.Frame(self.master, padding=10)
        frame_topo.pack(fill="x")

        frame_config = ttk.LabelFrame(
            frame_topo, text="Dados gerais", padding=10)
        frame_config.pack(fill="x", padx=5, pady=5)

        ttk.Label(frame_config, text="Versão XML").grid(
            row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_versao, width=12).grid(
            row=0, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(frame_config, text="Tipo Importador").grid(
            row=0, column=2, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_tipo_importador, width=12).grid(
            row=0, column=3, sticky="w", padx=5, pady=5)
        ttk.Label(frame_config, text="Cód. Importador").grid(
            row=0, column=4, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_cd_importador, width=20).grid(
            row=0, column=5, sticky="w", padx=5, pady=5)

        ttk.Label(frame_config, text="Certificado A1 (.pfx/.p12)").grid(row=1,
                                                                        column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_certificado, width=80).grid(
            row=1, column=1, columnspan=4, sticky="we", padx=5, pady=5)
        ttk.Button(frame_config, text="Selecionar", command=self.selecionar_certificado).grid(
            row=1, column=5, sticky="w", padx=5, pady=5)

        ttk.Label(frame_config, text="Senha certificado").grid(
            row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_senha, show="*",
                  width=30).grid(row=2, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(frame_config, text="Arquivo XML de saída").grid(
            row=2, column=2, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_config, textvariable=self.var_saida, width=60).grid(
            row=2, column=3, columnspan=2, sticky="we", padx=5, pady=5)
        ttk.Button(frame_config, text="Selecionar", command=self.selecionar_saida).grid(
            row=2, column=5, sticky="w", padx=5, pady=5)

        frame_item = ttk.LabelFrame(
            self.master, text="Preenchimento do item", padding=10)
        frame_item.pack(fill="x", padx=15, pady=5)

        campos = [
            ("Destinação", self.var_destinacao), ("Utilização", self.var_utilizacao),
            ("Tributação", self.var_tributacao), ("NCM", self.var_ncm),
            ("Cód. Suframa", self.var_cod_suframa), ("Número Documento",
                                                     self.var_numero_documento),
            ("Número Decreto",
             self.var_numero_decreto), ("Início (dd/mm/aaaa)", self.var_inicio),
            ("Fim (dd/mm/aaaa)", self.var_fim), ("Tipo Documento",
                                                 self.var_tipo_documento),
        ]

        for i, (rotulo, variavel) in enumerate(campos):
            linha, coluna = i // 5, (i % 5) * 2
            ttk.Label(frame_item, text=rotulo).grid(
                row=linha * 2, column=coluna, sticky="w", padx=5, pady=2)
            ttk.Entry(frame_item, textvariable=variavel, width=22).grid(
                row=linha * 2 + 1, column=coluna, sticky="w", padx=5, pady=2)

        frame_btns_item = ttk.Frame(frame_item)
        frame_btns_item.grid(
            row=4, column=0, columnspan=10, sticky="w", pady=10)
        ttk.Button(frame_btns_item, text="Adicionar item",
                   command=self.adicionar_item).pack(side="left", padx=5)
        ttk.Button(frame_btns_item, text="Limpar campos",
                   command=self.limpar_campos_item).pack(side="left", padx=5)
        ttk.Button(frame_btns_item, text="Remover selecionado",
                   command=self.remover_item_selecionado).pack(side="left", padx=5)

        frame_lista = ttk.LabelFrame(
            self.master, text="Itens adicionados", padding=10)
        frame_lista.pack(fill="both", expand=True, padx=15, pady=5)

        colunas = ("destinacao", "utilizacao", "tributacao", "ncm",
                   "cod_suframa", "num_doc", "num_dec", "ini", "fim")
        self.tree = ttk.Treeview(
            frame_lista, columns=colunas, show="headings", height=14)
        for col in colunas:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")

        scroll = ttk.Scrollbar(
            frame_lista, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        frame_rodape = ttk.Frame(self.master, padding=10)
        frame_rodape.pack(fill="x")
        ttk.Button(frame_rodape, text="Gerar XML assinado",
                   command=self.gerar_xml_assinado).pack(side="left", padx=5)
        ttk.Button(frame_rodape, text="Fechar",
                   command=self.master.destroy).pack(side="right", padx=5)

    # --- METODOS DE AÇÃO ---

    def selecionar_certificado(self):
        p = filedialog.askopenfilename(
            filetypes=[("Certificado A1", "*.pfx *.p12")])
        if p:
            self.var_certificado.set(p)

    def selecionar_saida(self):
        p = filedialog.asksaveasfilename(defaultextension=".xml")
        if p:
            self.var_saida.set(p)

    def limpar_campos_item(self):
        for v in [self.var_ncm, self.var_numero_documento, self.var_numero_decreto, self.var_inicio, self.var_fim]:
            v.set("")

    def adicionar_item(self):
        item = ItemMatriz(
            destinacao=self.var_destinacao.get(), utilizacao=self.var_utilizacao.get(),
            tributacao=self.var_tributacao.get(), ncm=self.var_ncm.get(),
            cod_suframa=self.var_cod_suframa.get(), numero_documento=self.var_numero_documento.get(),
            numero_decreto=self.var_numero_decreto.get(), inicio=self.var_inicio.get(),
            fim=self.var_fim.get(), tipo_documento_concessivo=self.var_tipo_documento.get()
        )
        self.itens.append(item)
        self.tree.insert("", "end", values=(item.destinacao, item.utilizacao, item.tributacao, item.ncm,
                         item.cod_suframa, item.numero_documento, item.numero_decreto, item.inicio, item.fim))
        self.limpar_campos_item()

    def remover_item_selecionado(self):
        sel = self.tree.selection()
        if sel:
            idx = self.tree.index(sel[0])
            self.tree.delete(sel[0])
            del self.itens[idx]

    def gerar_xml_assinado(self):
        try:
            if not self.var_certificado.get() or not self.itens:
                raise ValueError("Selecione o certificado e adicione itens.")

            cd_imp = "".join(filter(str.isdigit, self.var_cd_importador.get()))
            root = etree.Element(f"{{{NS_DIE}}}enviMatrizDIe", nsmap=NSMAP)
            root.set("versao", self.var_versao.get())
            root.set(f"{{{NS_XSI}}}schemaLocation", SCHEMA_LOC)

            matriz = etree.SubElement(root, f"{{{NS_DIE}}}MatrizDIe")
            inf = etree.SubElement(matriz, f"{{{NS_DIE}}}InfMatrizDIe")
            inf.set("Id", f"MatrizDIe{cd_imp.zfill(14)}")
            inf.set("versao", self.var_versao.get())

            imp = etree.SubElement(inf, f"{{{NS_DIE}}}Importador")
            etree.SubElement(
                imp, f"{{{NS_DIE}}}tipoImportador").text = self.var_tipo_importador.get()
            etree.SubElement(imp, f"{{{NS_DIE}}}cdImportador").text = cd_imp

            for i in self.itens:
                el = etree.SubElement(inf, f"{{{NS_DIE}}}ItemMatriz")
                etree.SubElement(el, f"{{{NS_DIE}}}cdNcmProdFinal").text = "".join(
                    filter(str.isdigit, i.ncm))
                etree.SubElement(
                    el, f"{{{NS_DIE}}}cdSuframa").text = i.cod_suframa
                etree.SubElement(
                    el, f"{{{NS_DIE}}}cdDestinacao").text = i.destinacao
                etree.SubElement(
                    el, f"{{{NS_DIE}}}cdUtilizacao").text = i.utilizacao
                etree.SubElement(
                    el, f"{{{NS_DIE}}}cdTributacao").text = i.tributacao
                etree.SubElement(el, f"{{{NS_DIE}}}numDecreto").text = "".join(
                    filter(str.isdigit, i.numero_decreto))
                etree.SubElement(
                    el, f"{{{NS_DIE}}}tpDocumentoConcessivo").text = i.tipo_documento_concessivo
                etree.SubElement(el, f"{{{NS_DIE}}}numDocumentoConcessivo").text = "".join(
                    filter(str.isdigit, i.numero_documento))

                # --- CORREÇÃO DE DATA PARA O PADRÃO SEFAZ (AAAAMMDD) ---
                def ajustar_data(txt):
                    limpo = "".join(filter(str.isdigit, txt))
                    if len(limpo) == 8:  # DDMMYYYY -> YYYYMMDD
                        return limpo[4:] + limpo[2:4] + limpo[:2]
                    return limpo

                etree.SubElement(
                    el, f"{{{NS_DIE}}}dtInicioBeneficio").text = ajustar_data(i.inicio)
                etree.SubElement(
                    el, f"{{{NS_DIE}}}dtFimBeneficio").text = ajustar_data(i.fim)

            limpar_formatacao_xml(root)
            root_assinado = assinar_xml(
                root, self.var_certificado.get(), self.var_senha.get())

            with open(self.var_saida.get(), "wb") as f:
                f.write(etree.tostring(root_assinado, encoding="UTF-8",
                        xml_declaration=True, pretty_print=False))

            messagebox.showinfo(
                "Sucesso", "XML gerado e assinado seguindo as regras da SEFAZ!")
        except Exception as e:
            messagebox.showerror("Erro", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    MatrizTributacaoApp(root)
    root.mainloop()
