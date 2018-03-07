using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using Loginauth.Models;
using System.Configuration;
using System.Web.Security;

namespace Loginauth.Controllers
{
    public class UsersController : Controller
    {
        private PacificEntities db = new PacificEntities();

        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified, ActivationCode")] User user)
        {
            bool statusOK = false;
            string message = null;

            //Model validation
            if (ModelState.IsValid)
            {
                //Email already exist
                if (IsEmailExist(user.Email))
                {
                    ModelState.AddModelError("EmailExist", "Email is already exist");
                    return View(user);
                }

                //Generate activation code
                user.ActivationCode = Guid.NewGuid();

                //Password hashing
                user.Password = Encrypt.Hash(user.Password);
                user.ConfirmPassword = Encrypt.Hash(user.ConfirmPassword);

                //Save to database
                db.Users.Add(user);
                db.SaveChanges();

                //Send email to user
                SendVerificationEmail(user.Email, user.ActivationCode.ToString());
                message = "Registration is completed. Please check you email to confirm : " + user.Email;
                statusOK = true;
            }
            else
            {
                message = "Improper model";
            }

            ViewBag.Message = message;
            ViewBag.StatusOK = statusOK;
            return View(user);
        } 

        public ActionResult VerifyAccount(string id)
        {
            //Verify account
            string message = null;
            try
            {
                var user = db.Users.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if (user != null)
                {
                    user.IsEmailVerified = true;
                    db.Configuration.ValidateOnSaveEnabled = false; //skip model validation
                    db.SaveChanges();
                }
                else
                {
                    message = "Invalid request";
                }
            }
            catch (Exception e)
            {
                //most likely invalid Guid
                message = e.Message;
            }

            ViewBag.Message = message;
            return View();
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(User model, string returnUrl = "")
        {
            string message = null;
            var user = db.Users.Where(a => a.Email == model.Email).FirstOrDefault();
            if (user != null)
            {
                if (user.IsEmailVerified)
                {
                    if (string.Compare(Encrypt.Hash(model.Password), user.Password) == 0)
                    {
                        message = "Incorrect password provided";
                    }
                    else
                    {
                        int timeout = model.RememberMe ? 525600 : 20; // 1 yr
                        var ticket = new FormsAuthenticationTicket(model.Email, model.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);

                        if (Url.IsLocalUrl(returnUrl))
                        {
                            //redirect to [Authorized] view where it was initially intended 
                            return Redirect(returnUrl);
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                }
                else
                {
                    message = "Please verify you email first before you can log in : " + user.Email;                   
                }
            }
            else
            {
                message = "Email is not registered";
            }

            ViewBag.Message = message;
            return View();
        }

        [Authorize]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login");
        }

        public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ForgotPassword(User model)
        {
            string message = null;
            bool statusOK = false;

            var user = db.Users.Where(a => a.Email == model.Email).FirstOrDefault();
            if (user != null)
            {
                db.Configuration.ValidateOnSaveEnabled = false; //skip model validation
                user.ResetPasswordCode = Guid.NewGuid();
                db.SaveChanges();

                //Send email for reset password
                SendForgotPasswordEmail(user.Email, user.ResetPasswordCode.ToString());
                message = "Reset password link has been sent to your email.";
                statusOK = true;
            }
            else
            {
                message = "Account not found";
            }

            ViewBag.Message = message;
            ViewBag.StatusOK = statusOK;
            return View();
        }

        public ActionResult VerifyResetPassword(string id)
        {
            string message = null;

            try
            {
                var user = db.Users.Where(a => a.ResetPasswordCode == new Guid(id)).FirstOrDefault();
                if (user != null)
                {
                    User model = new User();
                    model.ResetPasswordCode = new Guid(id);
                    return View(model);
                }
                else
                {
                    message = "Associated account not found!";
                }
            }
            catch (Exception e)
            {
                //most likely invalid Guid
                message = e.Message;
            }

            ViewBag.Message = message;
            return View();
        }

 
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult VerifyResetPassword(User model)
        {
            bool statusOK = false;
            string message = null;

            var user = db.Users.Where(a => a.ResetPasswordCode == model.ResetPasswordCode).FirstOrDefault();
            if (user != null)
            {
                user.Password = Encrypt.Hash(model.Password);
                user.ResetPasswordCode = null;
                db.Configuration.ValidateOnSaveEnabled = false; // skip model validation
                db.SaveChanges();
                message = "New password updated successfully";
                statusOK = true;
            }
            else
            {
                message = "Invalid reset code";
            }

            ViewBag.Message = message;
            ViewBag.StatusOK = statusOK;
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        [NonAction]
        public bool IsEmailExist(string email)
        {
            var user = db.Users.Where(a => a.Email == email).FirstOrDefault();
            return user != null;
        }

        [NonAction]
        public void SendVerificationEmail(string email, string activationCode)
        {
            var verifyUrl = "/Users/VerifyAccount/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress(ConfigurationManager.AppSettings["adminEmail"],
                                            ConfigurationManager.AppSettings["adminName"]);
            var toEmail = new MailAddress(email);
            var fromEmailPassword = ConfigurationManager.AppSettings["adminPassword"];
            var subject = "You account has been created!";
            string body = "<br />Please click link below to verify your account" +
                "<br /><br /><a href='" + link + "'>" + link + "</a>";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
            smtp.Send(message);
        }

        [NonAction]
        public void SendForgotPasswordEmail(string email, string passwordResetCode)
        {
            var verifyUrl = "/Users/VerifyResetPassword/" + passwordResetCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress(ConfigurationManager.AppSettings["adminEmail"],
                                            ConfigurationManager.AppSettings["adminName"]);
            var toEmail = new MailAddress(email);
            var fromEmailPassword = ConfigurationManager.AppSettings["adminPassword"];
            var subject = "Request for password reset";
            string body = "<br />Please click link below to reset your password" +
                "<br /><br /><a href='" + link + "'>" + link + "</a>";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
            smtp.Send(message);
        }
    }
}
