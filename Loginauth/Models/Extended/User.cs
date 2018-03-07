using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.Data;

namespace Loginauth.Models
{
    [MetadataType(typeof(UserMetaData))]
    public partial class User
    {
        public string ConfirmPassword { get; set; }
        public bool RememberMe { get; set; }

        public User()
        {
            IsEmailVerified = false;
        }
    }

    public class UserMetaData
    {
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Please enter email")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Please enter password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage ="Password should be at least 6 characters")]
        public string Password { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Please confirm password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Confirm password do not match")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }
    }
}