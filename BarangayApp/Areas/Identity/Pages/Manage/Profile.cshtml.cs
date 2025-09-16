using BarangayApp.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace BarangayApp.Areas.Identity.Pages.Manage
{
    public class ProfileModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public ProfileModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [TempData]
        public string? StatusMessage { get; set; }

        public string? CurrentCertificatePath { get; set; }

        public class InputModel
        {
            [Required]
            [Display(Name = "First Name")]
            public string? FirstName { get; set; }

            [Display(Name = "Middle Name")]
            public string? MiddleName { get; set; }

            [Required]
            [Display(Name = "Last Name")]
            public string? LastName { get; set; }

            [Display(Name = "Address")]
            public string? Address { get; set; }

            [Display(Name = "Gender")]
            public string? Gender { get; set; }

            [Range(13, 120, ErrorMessage = "Age must be between 13 and 120.")]
            [Display(Name = "Age")]
            public int Age { get; set; }

            [Phone]
            [StringLength(11, MinimumLength = 9, ErrorMessage = "Contact number must be between 9 and 11 digits")]
            [RegularExpression(@"^\d{9,11}$", ErrorMessage = "Contact number must be between 9 and 11 digits")]
            [Display(Name = "Contact Number")]
            public string? PhoneNumber { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("User not found.");

            Input = new InputModel
            {
                FirstName = user.FirstName,
                MiddleName = user.MiddleName,
                LastName = user.LastName,
                Address = user.Address,
                Gender = user.Gender,
                Age = user.Age,
                PhoneNumber = user.PhoneNumber
            };

            CurrentCertificatePath = user.BarangayCertificatePath;
            return Page();
        }
        //Change User info
        public async Task<IActionResult> OnPostSaveAsync()
        {
            if (!ModelState.IsValid) return Page();
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound("User not found.");
            bool updated = false;

            if (user.FirstName != Input.FirstName) { user.FirstName = Input.FirstName; updated = true; }
            if (user.MiddleName != Input.MiddleName) { user.MiddleName = Input.MiddleName; updated = true; }
            if (user.LastName != Input.LastName) { user.LastName = Input.LastName; updated = true; }
            if (user.Address != Input.Address) { user.Address = Input.Address; updated = true; }
            if (user.Gender != Input.Gender) { user.Gender = Input.Gender; updated = true; }
            if (user.Age != Input.Age) { user.Age = Input.Age; updated = true; }
            if (user.PhoneNumber != Input.PhoneNumber) { user.PhoneNumber = Input.PhoneNumber; updated = true; }

            if (updated)
            {
                var result = await _userManager.UpdateAsync(user);
                StatusMessage = result.Succeeded ? "Profile updated successfully!" : "Error updating profile.";
            }
            else
            {
                StatusMessage = "No changes were made.";
            }

            return RedirectToPage();
        }
        //Change User Email
        public async Task<IActionResult> OnPostChangeEmailAsync(string NewEmail)
        {
            if (string.IsNullOrEmpty(NewEmail))
            {
                StatusMessage = "Error: Email cannot be empty.";
                return RedirectToPage();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound("User not found.");
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, NewEmail);
            var result = await _userManager.ChangeEmailAsync(user, NewEmail, token);

            if (!result.Succeeded)
            {
                StatusMessage = "Error changing email.";
                return RedirectToPage();
            }

            user.UserName = NewEmail;
            await _userManager.UpdateAsync(user);
            await _signInManager.RefreshSignInAsync(user);
            StatusMessage = "Email updated successfully!";
            return RedirectToPage();
        }
        //Change User Password
        public async Task<IActionResult> OnPostChangePasswordAsync(string CurrentPassword, string NewPassword, string ConfirmPassword)
        {
            if (NewPassword != ConfirmPassword)
            {
                StatusMessage = "Error: New password and confirmation do not match.";
                return RedirectToPage();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound("User not found.");
            var result = await _userManager.ChangePasswordAsync(user, CurrentPassword, NewPassword);

            if (!result.Succeeded)
            {
                StatusMessage = "Error changing password.";
                return RedirectToPage();
            }
            await _signInManager.RefreshSignInAsync(user);
            StatusMessage = "Password updated successfully!";
            return RedirectToPage();
        }
    }
}