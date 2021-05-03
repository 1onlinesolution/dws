const nodemailer = require('nodemailer');
const MailServerError = require('./mailServerError');
const SmtpConfigurationError = require('./smtpConfigurationError');

// create reusable transporter object using the default SMTP transport
const createTransporterFromConfiguration = (smtpConfig) => nodemailer.createTransport(smtpConfig);

class EmailService {
  constructor(smtpConfig) {
    if (!smtpConfig) {
      throw new SmtpConfigurationError();
    }

    this.smtpConfig = smtpConfig;
  }

  createTransporter() {
    // create reusable transporter object using the default SMTP transport
    return createTransporterFromConfiguration(this.smtpConfig);
  }

  closeTransporter(transporter) {
    // only needed when using pooled connections
    transporter.close();
  }

  async sendOneOfEmails(transporter, message) {
    const notProduction = process.env.NODE_ENV !== 'production';

    try {
      await transporter.verify();
      const info = await transporter.sendMail(message);

      const { rejected, response, envelope, messageId } = info;

      return {
        envelope: envelope,
        response: response,
        messageId: messageId,
        ok: rejected.length <= 0 ? 1 : 0,
      };
    } catch (err) {
      const { code, command, responseCode, response, stack } = err;
      let msg = `code = ${code}, command = ${command}, responseCode = ${responseCode}, response = ${response}`;
      if (notProduction) {
        msg = `${msg}, stack = ${stack}`;
      }
      return Promise.reject(new MailServerError(msg));
    }
  }

  async sendEmail(message) {
    const notProduction = process.env.NODE_ENV !== 'production';

    // create reusable transporter object using the default SMTP transport
    const transporter = nodemailer.createTransport(this.smtpConfig);
    try {
      await transporter.verify();
      const info = await transporter.sendMail(message);

      // only needed when using pooled connections
      transporter.close();

      const { rejected, response, envelope, messageId } = info;

      return {
        envelope: envelope,
        response: response,
        messageId: messageId,
        ok: rejected.length <= 0 ? 1 : 0,
      };
    } catch (err) {
      const { code, command, responseCode, response, stack } = err;
      let msg = `code = ${code}, command = ${command}, responseCode = ${responseCode}, response = ${response}`;
      if (notProduction) {
        msg = `${msg}, stack = ${stack}`;
      }
      return Promise.reject(new MailServerError(msg));
    }
  }
}

module.exports = EmailService;
