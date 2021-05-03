const EmailService = require('./emailService');
const emailConfig = require('./defaultEmailConfig')({});

const err_message = 'cannot send email: invalid or no email';
/* eslint-disable indent */
const sendMail = async ({ message, email_username = process.env.EMAIL_USERNAME, email_password = process.env.EMAIL_PASSWORD }) => {
  if (!message) return Promise.reject(new Error(`${err_message} message`));
  if (!email_username) return Promise.reject(new Error(`${err_message} username`));
  if (!email_password) return Promise.reject(new Error(`${err_message} password`));

  // =============================================
  // See more at:
  // https://nodemailer.com/smtp/
  //
  const emailService = new EmailService({...emailConfig});

  try {
    await emailService.sendEmail(message);
    // `The message from '${message.from}' with subject '${message.subject}', was 'successfully' sent to '${message.to}'`
  } catch (err) {
    return Promise.reject(err);
  }
};
/* eslint-enable indent */

module.exports = sendMail;
