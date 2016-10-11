using System.ComponentModel.DataAnnotations.Schema;

namespace MSTaxis.IRepository.Infrastructure
{
    public interface IObjectState
    {
        [NotMapped]
        ObjectState ObjectState { get; set; }
    }
}
