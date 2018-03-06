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
                    db.Configuration.ValidateOnSaveEnabled = false; //skip check confirm password
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
        public ActionResult Login(UserLogin login, string returnUrl = "")
        {
            string message = null;
            var v = db.Users.Where(a => a.Email == login.Email).FirstOrDefault();
            if (v != null)
            {
                if (string.Compare(Encrypt.Hash(login.Password), v.Password) == 0)
                {
                    if (!v.IsEmailVerified)
                    {
                        message = "Please verify you email first before you can log in : " + v.Email;
                    }
                    else
                    {
                        int timeout = login.RememberMe ? 525600 : 20; // 1 yr
                        var ticket = new FormsAuthenticationTicket(login.Email, login.RememberMe, timeout);
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
                    message = "Incorrect password provided";
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
            var v = db.Users.Where(a => a.Email == email).FirstOrDefault();
            return v != null;
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
    }
}
