# EInvoicingSigner
A command prompt application used to serialize and sign tax payers documents before sending the documents to Egyptian Tax Authority. The application reads the invoice JSON file SourceDocumentJson.json and generates the canonical format of the JSON "CanonicalString.txt". The application signs the canonical genrated text and writes the output to the file Cades.txt. After that, the application will write the invoice json with signature into the file FullSignedDocument.json. 
This application has been developed to help in tracing signing documents issues. You can compare the generated canonical format, cades, and the full signed document with your generated version. Plus, you can use this tool from any progaming language C#, JAVA, or directly from database. All you need is writting the invoice JSON file, invoking the command prompt application, reading the signed invoice json, and sending it to "Egyptian Tax Authority".

The application takes three arguments
  * First argument is the application folder path. For example D:\EInvoicing
  * Second argument is the token pin.
  * Third argument is the certificate issuer. The default value for this argument is "Egypt Trust Sealing CA". For example \"Egypt Trust Sealing CA\" or \"Egypt Trust CA G6\"
  * Fourth argument is the library  name. For example eps2003csp11.dll or SignatureP11.dll
# How to use
1. Download the runtime version from https://drive.google.com/file/d/1jfkC_qfU56BSawRL4TcBrOssNudhcgTX/view?usp=sharing
2. Extract to a folder like D:\EInvoicing
3. Update the file SubmitInvoices.bat by your token PIN and application folder path
4. Update the file SourceDocumentJson.json with your invoice JSON.
5. Run the file SubmitInvoices.bat or SubmitInvoicesNewToken2024.bat
6. Take the content of FullSignedDocument.json and send it to "Egyptian Tax Authority" using any tool like Postman.
