var CAPICOM_CURRENT_USER_STORE = 2;
var CAPICOM_MY_STORE = 'My';
var CAPICOM_ROOT_STORE = 'Root';
var CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
var CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
var CADESCOM_CADES_X_LONG_TYPE_1 = 0x5d;
var CAPICOM_ENCODE_BASE64 = 0;
var CAPICOM_ENCODE_BINARY = 1;
var CADESCOM_BASE64_TO_BINARY = 0x01;
var CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE = 1;

var CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME = 0; // display name of the certificate subject
var CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME = 1; // display name of the issuer of the certificate
var CAPICOM_CERT_INFO_SUBJECT_EMAIL_NAME = 2; // email address of the certificate subject
var CAPICOM_CERT_INFO_ISSUER_EMAIL_NAME = 3; // email address of the issuer of the certificate
var CAPICOM_CERT_INFO_SUBJECT_UPN = 4; // UPN of the certificate subject. Introduced in CAPICOM 2.0
var CAPICOM_CERT_INFO_ISSUER_UPN = 5; // UPN of the issuer of the certificate. Introduced in CAPICOM 2.0
var CAPICOM_CERT_INFO_SUBJECT_DNS_NAME = 6; // DNS name of the certificate subject. Introduced in CAPICOM 2.0
var CAPICOM_CERT_INFO_ISSUER_DNS_NAME = 7; // DNS name of the issuer of the certificate. Introduced in CAPICOM 2.0

/**
 * btoa (string to Base64) implementation with UTF-8 support.
 */
window.btoa = function(input) {
	var keyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
		i = 0, output = '', chr1, chr2, chr3, enc1, enc2, enc3, enc4,
		utf8_encode = function (string) {
			string = string.replace(/\r\n/g, '\n');
			var utftext = '';
			for (var n = 0; n < string.length; n++) {
				var c = string.charCodeAt(n);
				if (c < 128) {
					utftext += String.fromCharCode(c);
				}
				else if((c > 127) && (c < 2048)) {
					utftext += String.fromCharCode((c >> 6) | 192);
					utftext += String.fromCharCode((c & 63) | 128);
				}
				else {
					utftext += String.fromCharCode((c >> 12) | 224);
					utftext += String.fromCharCode(((c >> 6) & 63) | 128);
					utftext += String.fromCharCode((c & 63) | 128);
				}
			}
			return utftext;
		};
	input = utf8_encode(input);
	while (i < input.length) {
		chr1 = input.charCodeAt(i++);
		chr2 = input.charCodeAt(i++);
		chr3 = input.charCodeAt(i++);
		enc1 = chr1 >> 2;
		enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		enc4 = chr3 & 63;
		if (isNaN(chr2)) {
			enc3 = enc4 = 64;
		} else if (isNaN(chr3)) {
			enc4 = 64;
		}
		output = output +
			keyStr.charAt(enc1) + keyStr.charAt(enc2) +
			keyStr.charAt(enc3) + keyStr.charAt(enc4);
	}
	return output;
};

/**
 * @class Util
 * @singleton
 */
var Util = {
	/**
	 * Creates object browser-independently.
	 * @param {String} name Object/ActiveX class name
	 */
	createObject: function(name) {
		switch (navigator.appName) {
			case 'Microsoft Internet Explorer':
				return new ActiveXObject(name);
			break;
			case 'Netscape':
			default:
				var cadesobject = document.getElementById('cadesplugin');
				return cadesobject.CreateObject(name);
		}
	},

	/**
	 * Extracts values from form fields.
	 * @param {Object} form
	 */
	getFormValues: function(form) {
		var i, field, out = {};
		for (i in form.elements) {
			if (Object.hasOwnProperty.call(form.elements, i)) {
				field = form.elements[i];
				if (field && field.name && typeof field.value != 'undefined') {
					out[field.name] = field.value;
				}
			}
		}

		return out;
	},

	toBase64: function(form) {
		var rawData = form.data.value;
		var base64Data = btoa(rawData);
		form.elements.base64Data.value = base64Data || '';
	},

	fillCertificatesCombo: function() {
 		var combo1 = document.getElementById('certificates1');
		var combo2 = document.getElementById('certificates2');

		var store = Util.createObject('CAPICOM.Store');
		store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
		var certificates = store.Certificates;
		try {
			for (var i = 1; i <= certificates.Count; i++) { // index starts from 1
				var certificate = certificates.Item(i);

				var option1 = document.createElement('option');
				option1.text = certificate.SubjectName;
				option1.value = certificate.SubjectName;

				var option2 = document.createElement('option');
				option2.text = certificate.SubjectName;
				option2.value = certificate.SubjectName;
				try {
					combo1.add(option1, null); //Standard
					combo2.add(option2, null); 
				} catch (error) {
					combo1.add(option1); // IE only
					combo2.add(option2); 
				}
			}
		} finally {
			store.Close();
		}
	},

	findCertificate: function(subjectName) {
		var store = Util.createObject('CAPICOM.Store');
		store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_ROOT_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
		try {
			var certificates = store.Certificates.Find(CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME, subjectName);
			if (certificates.Count != 1) {
				Util.info('count is: ' + certificates.Count);
				return;
			}

			var certificate = certificates.Item(1);

			Util.info('subjectName: ' + certificate.SubjectName + ' serial: ' + certificate.SerialNumber);
		} finally {
			store.Close();
		}
	},

	bindFileInputs: function() {
		var FileReader = window.FileReader,
			i, file, files = document.getElementsByTagName('input');
		for (i = 0; i < files.length; i++) {
			file = files[i];
			if (file.type !== 'file') {
				continue;
			}
			if (FileReader) {
				// we can use modern APIs here
				file.fo = document.querySelector('[name=' + file.getAttribute('for') + ']');
				file.addEventListener('change', function(event) {
					var input = event.target,
						entry = input.files[0];
					if (!entry) {
						return;
					}

					var reader = new FileReader();
					reader.onload = function(e) {
						input.fo &&
							(input.fo.value = reader.result);
					};
					reader.onerror = function(e) {
						Util.error('File API error', reader.error.code);
					};
					reader.readAsText(entry);
				});
			} else {
				file.parentNode.removeChild(file);
			}
		}

		var ActiveXObject = window.ActiveXObject;
		if (!ActiveXObject) {
			return;
		}

		var load, loads = document.querySelectorAll('.load');
		for (i = 0; i < loads.length; i++) {
			load = loads[i];
			if (load.tagName !== 'BUTTON') {
				continue;
			}
			load.onclick = function(event) {
				var btn = event ? event.target : document.activeElement,
					src = this.nextSibling,
					dst = this.form.elements[btn.getAttribute('to')],
					filename = src.value,
					fs = new ActiveXObject("Scripting.FileSystemObject");
				if (!fs.FileExists(filename)) {
					Util.error('File "' + filename + '" does not exist');
					return;
				}
				var file = fs.OpenTextFile(filename, 1, true);
				dst.value = file.ReadAll();
				file.Close();
			}
		}
	},

	bindFileOutputs: function() {
		var ActiveXObject = window.ActiveXObject,
			i, save, saves = document.querySelectorAll('.save');
		for (i = 0; i < saves.length; i++) {
			save = saves[i];
			if (save.tagName !== 'BUTTON') {
				continue;
			}
			if (ActiveXObject) {
				save.onclick = function(event) {
					var btn = event ? event.target : document.activeElement,
						src = this.form.elements[btn.getAttribute('from')],
						dst = this.nextSibling,
						filename = dst.value,
						fs = new ActiveXObject("Scripting.FileSystemObject");
					var file = fs.CreateTextFile(filename, true);
					file.Write(src.value);
					file.Close();
				}
			} else {
				save.parentNode.removeChild(save);
			}
		}
	},

	info: function(message) {
		alert(message);
	},

	error: function(message, data) {
		alert(message + (data ? '\n\n' + data : ''));
	}
};

/**
 * @class Logic
 * @singleton
 */
var Logic = {
	/**
	 * Signs given document with given signature.
	 */
	sign: function(subjectName, documentData, tsaUrl) {
		var store = Util.createObject('CAPICOM.Store');
		store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

		var certificates = store.Certificates.Find(CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME, subjectName);
		if (certificates.Count == 0) {
			Util.error('Certificate not found');
			return;
		}

		try {
			var signer = Util.createObject('CAdESCOM.CPSigner');
			signer.Certificate = certificates.Item(1);
			signer.TSAAddress = tsaUrl;

			var signedData = Util.createObject('CAdESCOM.CadesSignedData');
			signedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
			signedData.Content = documentData;

			var signedMessage = signedData.SignCades(signer, CADESCOM_CADES_X_LONG_TYPE_1, true, CAPICOM_ENCODE_BASE64);
			Util.info('Signed successfully!');
		} catch (err) {
			Util.error('Failed to create signature. ', err);
			return;
		} finally {
			store.Close();
		}

		return signedMessage;
	},

	/**
	 * Verifies given signature with given document.
	 */
	verify: function(document, signature) {
		try {
			var signedData = Util.createObject('CAdESCOM.CadesSignedData');
			signedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
			signedData.Content = document;

			signedData.VerifyCades(signature, CADESCOM_CADES_X_LONG_TYPE_1, true);
		} catch (err) {
			Util.error('Failed to verify signature. ', err);
			return false;
		}

		return true;
	},

	/**
	 * Co-signs given document with given signature.
	 */
	coSign: function(subjectName, documentData, signatureData, tsaUrl) {
		var store = Util.createObject('CAPICOM.Store');
		store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

		var certificates = store.Certificates.Find(CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME, subjectName);
		if (certificates.Count == 0) {
			Util.error('Certificate not found');
			return;
		}

		try {
			var signer = Util.createObject('CAdESCOM.CPSigner');
			signer.Certificate = certificates.Item(1);
			signer.TSAAddress = tsaUrl;

			var signedData = Util.createObject('CAdESCOM.CadesSignedData');
			signedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
			signedData.Content = documentData;

			signedData.VerifyCades(signatureData, CADESCOM_CADES_X_LONG_TYPE_1, true);
			var signedMessage = signedData.CoSignCades(signer, CADESCOM_CADES_X_LONG_TYPE_1, CAPICOM_ENCODE_BASE64);

			Util.info('Signed successfully!');
		} catch (err) {
			Util.error('Failed to create signature.', err);
			return;
		} finally {
			store.Close();
		}

		return signedMessage;
	},

	/**
	 * Returns data about signature.
	 * This method requires original document data because of API features.
	 * @return {Object[]}
	 */
	getSigners: function(document, signature) {
		try {
			var signedData = Util.createObject('CAdESCOM.CadesSignedData');
			signedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
			signedData.Content = document;

			signedData.VerifyCades(signature, CADESCOM_CADES_X_LONG_TYPE_1, true);
		} catch (err) {
			Util.error('Failed to open signature. ', err);
			return [];
		}

		try {
			var i, signer, certificate, out = [], length = signedData.Signers.Count;
			for (i = 1; i <= length; i++) { // index starts from 1
				signer = signedData.Signers.Item(i);
				certificate = signer.Certificate;
				out.push({
					serial: certificate.SerialNumber,
					subject: certificate.SubjectName,
					issuer: certificate.IssuerName,
					validFrom: certificate.ValidFromDate,
					validTo: certificate.ValidToDate,
					// TODO new Date()
					timestamp: signer.SignatureTimeStampTime
				});
			}
		} catch (err) {
			Util.error('Failed to get signers. ', err);
			return [];
		}

		return out;
	},

	/**
	 * Extracts certificate name from raw name data.
	 * @param {String} raw Raw name data
	 */
	extractName: function(raw) {
		var i, match, spaces = ['CN', 'C', 'OU', 'O'];
		for (i = 0; i < spaces.length; i++) {
			if (match = this.extractString(raw, spaces[i])) {
				return match;
			}
		}

		return '';
	},

	/**
	 * Extracts name of given space from raw name data.
	 * @param {String} raw Raw name data
	 * @param {String} space 'CN', 'C', etc.
	 */
	extractString: function(raw, space) {
		space = space || 'CN';
		var match = RegExp(space + '=([^,]*)').exec(raw);

		return match ?
			match[1] :
			'';
	}
};

/**
 * @class View
 * @singleton
 */
var View = {
	verify: function(form) {
		var data = Util.getFormValues(form),
			result = Logic.verify(data.document, data.signature);

		Util.info('Signature is ' + (result ? 'VALID' : 'INVALID'));
	},

	sign: function(form) {
		var data = Util.getFormValues(form),
			signature = Logic.sign(
				Logic.extractName(data.certificate),
				data.base64Data,
				data.tsaUrl
			);

		form.elements.signature.disabled = false;
		form.elements.signature.value = signature || '';

		return signature;
	},

	signAndVerify: function(form) {
		var data = Util.getFormValues(form),
			signature = this.sign(form),
			result = Logic.verify(data.base64Data, signature);

		Util.info('Signature is ' + (result ? 'VALID' : 'INVALID'));
	},

	coSign: function(form) {
		var data = Util.getFormValues(form),
			signature = Logic.coSign(
				Logic.extractName(data.certificate),
				data.base64Data,
				data.origSignature,
				data.tsaUrl
			);

		form.elements.signature.disabled = false;
		form.elements.signature.value = signature || '';

		return signature;
	},

	coSignAndVerify: function(form) {
		var data = Util.getFormValues(form),
			signature = this.coSign(form),
			result = Logic.verify(data.base64Data, signature);

		Util.info('Signature is ' + (result ? 'VALID' : 'INVALID'));
	},

	showSigners: function(form) {
		var data = Util.getFormValues(form),
			signers = Logic.getSigners(data.document, data.signature),
			i, signer, msg = '';

		for (i = 0; i < signers.length; i++) {
			signer = signers[i];

			msg += '#' + (i + 1) + '\n' +
			(signer.timestamp || '') + ' ' +
			(signer.serial || '') + ' ' +
			(signer.subject || '') + ' ' +
			(signer.issuer || '') + ' ' +
			(signer.validSince || '') + ' ' +
			(signer.validTill || '') + '\n\n';
		}

		msg &&
			Util.info(msg);
	}
};