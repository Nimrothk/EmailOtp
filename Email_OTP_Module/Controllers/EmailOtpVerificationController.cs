using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;

namespace EmailOtpVerification.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Email_OTP_Module : ControllerBase
    {
        private const int Otp_Validity = 1;
        private const string Allowed_Domain = ".dso.org.sg"; // Testable domain = gmail.com
        private const int Max_Attempts = 10;

        private static readonly ConcurrentDictionary<string, (string OtpHash, DateTime ExpiryTime, int Attempts)> storeOtp = new();

        [HttpPost("Generate")]
        public async Task<IActionResult> GenerateOtpEmail(string user_Email)
        {
            string email = user_Email.ToLowerInvariant();
            if (!IsValidEmail(email) || !email.EndsWith(Allowed_Domain))
            {
                return BadRequest("STATUS_EMAIL_INVALID");
            }

            if (storeOtp.ContainsKey(email) && storeOtp[email].Attempts >= Max_Attempts)
            {
                return BadRequest("STATUS_TOO_MANY_ATTEMPTS");
            }

            string otp = GenerateSecureRandomOtp();  // Using cryptographically to generate random secure OTP

            string otpHash = HashOtp(otp);  // Hash the OTP before storing it

            storeOtp[email] = (otpHash, DateTime.UtcNow.AddMinutes(Otp_Validity), 0); // Store the OTP

            string emailBody = $"Your OTP Code is {otp}. The code is valid for {Otp_Validity} minute.";

            bool emailSent = await SendEmailAsync(email, emailBody); // Send the OTP
            if (emailSent)
            {
                return Ok("STATUS_EMAIL_OK");
            }
            else
            {
                return StatusCode(500, "STATUS_EMAIL_FAIL");
            }
        }

        [HttpPost("Validate")]
        public IActionResult ValidateOtp(ValidateOtpRequest request)
        {
            string email = request.Email.ToLowerInvariant();
            if (!storeOtp.ContainsKey(email))
            {
                return BadRequest("No OTP generated for this email.");
            }

            var (storedOtpHash, expiryTime, attempts) = storeOtp[email];

            if (attempts >= Max_Attempts)
            {
                storeOtp.TryRemove(email, out _);
                return BadRequest("STATUS_OTP_FAIL");
            }

            if (DateTime.UtcNow > expiryTime)
            {
                storeOtp.TryRemove(email, out _);
                return BadRequest("STATUS_OTP_TIMEOUT");
            }

            if (VerifyOtpHash(request.Otp, storedOtpHash)) // Verify the OTP by comparing the hash
            {
                storeOtp.TryRemove(email, out _);
                return Ok("STATUS_OTP_OK");
            }

            storeOtp[email] = (storedOtpHash, expiryTime, attempts + 1); // Otp attemped check

            return BadRequest("Invalid OTP.");
        }

        private static bool IsValidEmail(string email)
        {
            try
            {
                var mailAddress = new MailAddress(email);
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Generate a 6-digit numeric OTP
        private static string GenerateSecureRandomOtp()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[4];
                rng.GetBytes(randomBytes);

                int otp = BitConverter.ToInt32(randomBytes, 0) & 0x7FFFFFFF;
                otp = otp % 1000000;

                return otp.ToString("D6");
            }
        }

        private static string HashOtp(string otp)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(otp);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        private static bool VerifyOtpHash(string otp, string storedOtpHash)
        {
            string otpHash = HashOtp(otp);
            return otpHash == storedOtpHash;
        }

        private static async Task<bool> SendEmailAsync(string email_address, string email_body)
        {
            try
            {
                string from = "Example@test.dso.org.sg"; // Replace a email address  testable domain = gmail.com
                string appPassword = "**************"; // Replace a key

                MailMessage message = new MailMessage
                {
                    From = new MailAddress(from),
                    Subject = "Your OTP Code",
                    Body = email_body
                };
                message.To.Add(email_address);

                using (SmtpClient smtp = new SmtpClient("smtp.gmail.com"))
                {
                    smtp.Port = 587;
                    smtp.Credentials = new System.Net.NetworkCredential(from, appPassword);
                    smtp.EnableSsl = true;

                    await smtp.SendMailAsync(message);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public class ValidateOtpRequest
    {
        public string Email { get; set; }
        public string Otp { get; set; }
    }
}
