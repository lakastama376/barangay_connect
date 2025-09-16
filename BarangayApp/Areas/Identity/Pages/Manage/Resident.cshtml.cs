using BarangayApp.Areas.Identity.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BarangayApp.Areas.Identity.Pages.Manage
{
    [Authorize(Roles = "Admin,Staff")]
    public class ResidentModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        [BindProperty(SupportsGet = true)]
        public string Search { get; set; }
        public List<ApplicationUser> Residents { get; set; } = new();

        public ResidentModel(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
        }
        public async Task OnGetAsync()
        {
            var users = userManager.Users.ToList();
            Residents = new List<ApplicationUser>();

            // Hidden info for Admin and Staff
            foreach (var user in users)
            {
                var roles = await userManager.GetRolesAsync(user);
                if (!roles.Contains("Admin") && !roles.Contains("Staff"))
                {
                    Residents.Add(user);
                }
            }
            // Search for Resident info
            if (!string.IsNullOrEmpty(Search))
            {
                var search = Search.ToLower();
                Residents = Residents.Where(r =>
                    (!string.IsNullOrEmpty(r.FirstName) && r.FirstName.ToLower().Contains(search)) ||
                    (!string.IsNullOrEmpty(r.LastName) && r.LastName.ToLower().Contains(search)) ||
                    (!string.IsNullOrEmpty(r.MiddleName) && r.MiddleName.ToLower().Contains(search)) ||
                    (!string.IsNullOrEmpty(r.Email) && r.Email.ToLower().Contains(search))
                ).ToList();
            }
        }
        // Remove Account of Resident only for Admin
        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            if (!User.IsInRole("Admin"))
            {
                return Forbid();
            }

            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            await userManager.DeleteAsync(user);
            return RedirectToPage(new { Search });
        }

    }
}

