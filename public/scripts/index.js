const showBtn = document.querySelectorAll("#show-btn"),
  closeBtn = document.querySelectorAll("#close-btn");

const toggleBtn = () => {
  showBtn.forEach((item, index) => {
    item.addEventListener("click", () => {
      closeBtn[index].classList.toggle("toggleDisplay");
    });
  });
};
toggleBtn();
