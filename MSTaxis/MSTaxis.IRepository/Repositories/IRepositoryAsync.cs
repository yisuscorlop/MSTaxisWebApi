using MSTaxis.IRepository.Infrastructure;
using System.Threading;
using System.Threading.Tasks;

namespace MSTaxis.IRepository.Repositories
{
    public interface IRepositoryAsync<TEntity> : IRepository<TEntity> where TEntity : class, IObjectState
    {
        Task<TEntity> FindAsync(params object[] keyValues);
        Task<TEntity> FindAsync(CancellationToken cancellationToken, params object[] keyValues);
        Task<bool> DeleteAsync(params object[] keyValues);
        Task<bool> DeleteAsync(CancellationToken cancellationToken, params object[] keyValues);
        IRepositoryAsync<T> GetRepositoryAsync<T>() where T : class, IObjectState;
    }
}
